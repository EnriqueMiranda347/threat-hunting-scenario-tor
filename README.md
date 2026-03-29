# threat-hunting-scenario-tor
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/EnriqueMiranda347/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan
- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table
Queried for any files containing the string “tor” or “firefox”. Discovered user **emvm** downloaded a Tor installer. Shortly after, multiple Tor-related files were created/copied to the user’s Desktop, including a file called `tor-shopping-list.lnk` at `2026-03-28T16:57:39.3853346Z`.

Events began at `2026-03-28T16:44:50.9669942Z`.

**Query used to locate events:**
```kql
DeviceFileEvents
| where DeviceName == "pc2"
| where FileName contains "tor" or FileName contains "firefox"
| where InitiatingProcessAccountName == "emvm"
| where Timestamp >= datetime(2026-03-28T16:44:50.9669942Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1214" height="770" alt="image" src="https://github.com/user-attachments/assets/ded088e9-618a-4e54-8fe8-35d36266189f" />


---
### 2. Searched the DeviceProcessEvents Table
Searched for any ProcessCommandLine containing “tor-browser-windows-x86_64-portable-15.0.8.exe”. At 2026-03-28T16:46:01.4354348Z, user emvm on device pc2 executed the file from the Downloads folder, triggering a silent/portable installation.

**Query used to locate events:**
```kql
DeviceProcessEvents
| where DeviceName == "pc2"
| where AccountName == "emvm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.8.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="968" height="756" alt="image" src="https://github.com/user-attachments/assets/eff4475a-6d55-454f-abe7-3f7e368f223d" />



---
### 3. Searched the DeviceProcessEvents Table for TOR Browser Execution
Searched for indication that user emvm actually opened the Tor Browser. Multiple instances of firefox.exe (Tor) and tor.exe/ tor.browser.exe were spawned. Evidence confirms the browser was opened at approximately 2026-03-28T16:48:45.593336Z.

**Query used to locate events:**
```kql
DeviceProcessEvents
| where DeviceName == "pc2"
| where AccountName == "emvm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1210" height="724" alt="image" src="https://github.com/user-attachments/assets/f7a0acad-2499-4b5c-995b-1b1c8e10c933" />


---
### 4. Searched the DeviceNetworkEvents Table for TOR Network Connections
Searched for connections over known Tor ports. The log confirms active use of the Tor Browser: firefox.exe successfully connected to the loopback address 127.0.0.1 on port 9151 (standard Tor Browser control port).

**Query used to locate events:**
```kql
DeviceNetworkEvents
| where DeviceName == "pc2"
| where InitiatingProcessAccountName == "emvm"
| where RemotePort in (9001, 9030, 9050, 9051, 9150, 9151)
| where InitiatingProcessFileName has_any ("tor", "firefox")
| where Timestamp == datetime("2026-03-28T16:48:56.8605748Z")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1216" height="776" alt="image" src="https://github.com/user-attachments/assets/bcdb0bf3-abb8-43dd-b5f1-3c02df40445b" />

---
### Chronological Event Timeline

- 2026-03-28T16:44:50Z — File discovery / download of Tor portable installer by user emvm.
- 2026-03-28T16:46:01Z — Process creation: Execution of tor-browser-windows-x86_64-portable-15.0.8.exe from Downloads folder (silent/portable installation).
- 2026-03-28T16:48:01Z — Silent installation completes; core binaries (tor.exe, firefox.exe) created on Desktop.
- 2026-03-28T16:48:45Z — Tor Browser officially launched (firefox.exe + tor.exe spawned).
- 2026-03-28T16:48:56Z — Internal handshake: firefox.exe connects to 127.0.0.1:9151.
- 2026-03-28T16:49:58Z — External Tor circuit: tor.exe connects to remote Tor relay (port 9001).
- 2026-03-28T16:54:34Z — High volume of child firefox.exe processes (active browsing/tabs).
- 2026-03-28T16:57:39Z — Creation of tor-shopping-list.lnk on Desktop.

---
### Summary
On March 28, 2026, user emvm on workstation pc2 intentionally bypassed corporate web filtering and security policies by installing and utilizing the Tor Browser (version 15.0.8 portable). The activity used a portable installation directly to the Desktop to avoid standard detection.
Evidence confirms a successful policy violation: active Tor circuit establishment combined with creation of a "shopping list" file, suggesting possible anonymous browsing or dark web activity. This represents an insider threat risk that warrants immediate administrative action and forensic review.

---
### Response Taken
TOR usage was confirmed on endpoint pc2 by user emvm. The device was isolated, and the user's direct manager was notified.









