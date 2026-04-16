<img width="1000" height="691" alt="image" src="https://github.com/user-attachments/assets/02f9e07b-172a-4264-8b85-f5d3fc859076" />

## Executive Summary

On February 25–26, 2026, the threat actor group **Scattered Spider** (UNC3944 / Octo Tempest) successfully compromised the account `m.smith@lognpacific.org` using a combination of credential theft and **MFA Fatigue (Push Bombing)**.  

The attacker originated from IP `205.147.16.190` (Netherlands), created hidden inbox rules for persistence, and launched a targeted **Business Email Compromise (BEC)** campaign against internal financial contacts.  

**Containment:** The compromised account was immediately disabled.  

**Key MITRE Technique:** T1564.008 – Hide Artifacts: Email Hiding Rules

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [1. Incident Overview](#1-incident-overview)
- [2. Evidence & Query Ledger](#2-evidence--query-ledger)
  - [Phase 1: Identification of Compromised Identity](#phase-1-identification-of-compromised-identity)
  - [Phase 2: Attacker Geo-Location & Infrastructure](#phase-2-attacker-geo-location--infrastructure)
  - [Phase 3: The MFA Fatigue Attack](#phase-3-the-mfa-fatigue-attack)
  - [Phase 4: Attacker Device Fingerprint](#phase-4-attacker-device-fingerprint)
  - [Phase 5: Persistence & Evasion](#phase-5-persistence--evasion)
  - [Phase 6: Targeted BEC Campaign](#phase-6-targeted-bec-campaign)
  - [Phase 7: Correlation & Mitigation](#phase-7-correlation--mitigation)
- [3. Summary of Findings](#3-summary-of-findings)
- [4. Recommendations & Lessons Learned](#4-recommendations--lessons-learned)
- [KQL Queries ](#kql-queries)
- [Timeline](#timeline)

---

## 1. Incident Overview

This report documents a confirmed **Business Email Compromise (BEC)** and **MFA Fatigue** attack attributed to **Scattered Spider**.  

The attack originated from anonymized infrastructure in the **Netherlands** and successfully bypassed identity protections to establish persistence and target internal financial contacts.

---

## 2. Evidence & Query Ledger

### Phase 1: Identification of Compromised Identity

**Discovery:** Initial investigation into suspicious email patterns identified `m.smith@lognpacific.org` as the primary point of compromise.
<img width="926" height="739" alt="image" src="https://github.com/user-attachments/assets/c8862086-f918-4d8a-9b85-bea872b538b0" />

```kql
// Identifying the compromised account
EmailEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00) .. datetime(2026-02-26T23:00:00))
| where RecipientEmailAddress contains "m.smith"
| order by TimeGenerated desc
```

---

## Phase 2: Attacker Geo-Location & Infrastructure

Evidence: The attacker utilized IP 205.147.16.190 originating from the Netherlands (NL).
<img width="795" height="702" alt="image" src="https://github.com/user-attachments/assets/eae6a594-ea01-4d34-989b-dc5d22432e2b" />


Attacker Source and Geo-Origin
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25T21:00:00) .. datetime(2026-02-26T23:00:00))
| where ResultSignature == "SUCCESS" and Identity == "Mark Smith"
| where IPAddress == "205.147.16.190"
| project TimeGenerated, Location, IPAddress, ResultSignature
| order by TimeGenerated desc
```

---

## Phase 3: The MFA Fatigue Attack

Evidence: The logs show a "Push Spam" or MFA Fatigue attempt. The user initially denied the prompts (Error 50074) before eventually approving. Fatigue intensity recorded at 3 failed attempts.
<img width="752" height="679" alt="image" src="https://github.com/user-attachments/assets/ad87c7e3-12f1-472e-8aa2-760b17869263" />
<img width="810" height="469" alt="image" src="https://github.com/user-attachments/assets/2e75ebb1-dc99-4a5b-b676-a2de64f20155" />


MFA Error Code 50074 and Fatigue Intensity Count
```kql
SigninLogs
| where TimeGenerated > todatetime('2026-02-25T21:59:52.7988431Z')
| where IPAddress == "205.147.16.190"
| where Identity == "Mark Smith" and ResultType == "50074" 
| summarize FatigueIntensity = count()
```

---

## Phase 4: Attacker Device Fingerprint

Evidence: The actor utilized One Outlook Web via a Linux operating system running Firefox 147.0.
<img width="966" height="437" alt="image" src="https://github.com/user-attachments/assets/016a7ff1-9d8c-4769-9572-317849c8e29d" />


App, OS, and Browser Version
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25T13:00:00) .. datetime(2026-02-26T21:00:00))
| where Identity == "Mark Smith" and IPAddress == "205.147.16.190"
| project TimeGenerated, AppDisplayName, DeviceDetail.operatingSystem, DeviceDetail.browser
| order by TimeGenerated desc
```

---

## Phase 5: Persistence & Evasion

Evidence: The attacker created a hidden rule named . to move emails containing keywords like "invoice" or "wire" to hidden folders and applied StopProcessRules.
<img width="1299" height="623" alt="image" src="https://github.com/user-attachments/assets/8e5e061c-774f-44c9-9272-ac3815548fb1" />


Post-Auth Actions and Malicious Rule Details
```kql 
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T13:00:00) .. datetime(2026-02-26T21:00:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| project TimeGenerated, ActionType, AccountDisplayName, RawEventData.Parameters
| order by TimeGenerated asc
```

---

## Phase 6: Targeted BEC Campaign
Evidence: The actor sent an internal phishing email to j.reynolds@lognpacific.org regarding fraudulent payments.
<img width="1259" height="622" alt="image" src="https://github.com/user-attachments/assets/ffe4bfe9-e7ec-45f3-b659-f45c7638b12f" />



BEC Target and Email Direction
```kql
EmailEvents
| where TimeGenerated between (datetime('2026-02-25T21:56:24Z') .. datetime('2026-02-25T22:10:10Z'))
| where DeliveryAction == "Delivered"
| project TimeGenerated, DeliveryAction, EmailDirection, RecipientEmailAddress, SenderFromAddress, Subject, To, Cc, RecipientDomain, SenderIPv4
```

---

## Phase 7: Correlation & Mitigation

Evidence: The session was correlated via ID 00225cfa-a0ff-fb46-a079-5d152fcdf72a. Conditional Access was notApplied, facilitating the breach.
<img width="826" height="426" alt="image" src="https://github.com/user-attachments/assets/b0c48573-bd0f-439b-9cff-5be2432a928e" />



SharePoint Access and Correlation
```kql
SigninLogs
| where TimeGenerated between (datetime('2026-02-25T21:56:24Z') .. datetime('2026-02-25T22:10:10Z'))
| where IPAddress == "205.147.16.190"
| project SessionId, ConditionalAccessStatus, AppDisplayName
```

---

## 3. Summary of Findings

Threat Actor: Scattered Spider (UNC3944 / Octo Tempest)
Initial Vector: Likely InfoStealer (Credential theft) followed by MFA Fatigue (Push Bombing)
Key MITRE ATT&CK Technique: T1564.008 - Hide Artifacts: Email Hiding Rules
Containment Status: Account Disabled (Immediate containment performed)

---

## 4. Recommendations & Lessons Learned
Immediate Recommendations

Enforce Number Matching or Passwordless authentication (FIDO2 / Passkeys) to defeat MFA Fatigue.
Enable Continuous Access Evaluation (CAE) and stricter Conditional Access policies.
Implement Inbox Rule monitoring and alerting for suspicious rules (especially hidden or single-dot named rules).
Block high-risk countries or use geofencing where business allows.

---

Lessons Learned

MFA Fatigue remains highly effective against push-based MFA.
Hidden inbox rules (T1564.008) are a common persistence technique used by Scattered Spider.
Rapid correlation between SigninLogs, CloudAppEvents, and EmailEvents is critical for BEC detection.

---


## KQL Queries 
All queries combined for easy copy-paste into Microsoft Sentinel or Defender:
```kql



//Compromised Account
EmailEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00) .. datetime(2026-02-26T23:00:00))
| where RecipientEmailAddress contains "m.smith"
| order by TimeGenerated desc

//Attacker IP and Geo
SigninLogs
| where TimeGenerated between (datetime(2026-02-25T21:00:00) .. datetime(2026-02-26T23:00:00))
| where ResultSignature == "SUCCESS" and Identity == "Mark Smith"
| where IPAddress == "205.147.16.190"
| project TimeGenerated, Location, IPAddress, ResultSignature
| order by TimeGenerated desc

//MFA Fatigue
SigninLogs
| where TimeGenerated > todatetime('2026-02-25T21:59:52.7988431Z')
| where IPAddress == "205.147.16.190"
| where Identity == "Mark Smith" and ResultType == "50074"
| summarize FatigueIntensity = count()

//Device Fingerprint
SigninLogs
| where TimeGenerated between (datetime(2026-02-25T13:00:00) .. datetime(2026-02-26T21:00:00))
| where Identity == "Mark Smith" and IPAddress == "205.147.16.190"
| project TimeGenerated, AppDisplayName, DeviceDetail.operatingSystem, DeviceDetail.browser
| order by TimeGenerated desc

//Malicious Inbox Rule
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T13:00:00) .. datetime(2026-02-26T21:00:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| project TimeGenerated, ActionType, AccountDisplayName, RawEventData.Parameters
| order by TimeGenerated asc

//BEC Email
EmailEvents
| where TimeGenerated between (datetime('2026-02-25T21:56:24Z') .. datetime('2026-02-25T22:10:10Z'))
| where SenderFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, EmailDirection, RecipientEmailAddress, Subject, DeliveryAction

//Session Correlation
SigninLogs
| where TimeGenerated between (datetime('2026-02-25T21:56:24Z') .. datetime('2026-02-25T22:10:10Z'))
| where IPAddress == "205.147.16.190"
| project SessionId, ConditionalAccessStatus, AppDisplayName
```

---

## Timeline

| Time (UTC)             | Event                              | Details                                      |
|------------------------|------------------------------------|----------------------------------------------|
| 2026-02-25 21:00:00   | Initial sign-ins                   | From IP 205.147.16.190 (Netherlands)         |
| 2026-02-25 21:59:52   | MFA Fatigue attack begins          | Error 50074 – 3 push denials                 |
| 2026-02-25 ~22:00     | Successful authentication          | Attacker gains access to account             |
| 2026-02-25 ~22:00     | Malicious Inbox Rule created       | Hidden rule named "." with StopProcessRules  |
| 2026-02-25 21:56–22:10| BEC phishing email sent            | Targeted j.reynolds@lognpacific.org          |
| 2026-02-26            | Account disabled                   | Immediate containment completed              |

---

- Report Author: Enrique Miranda
- Date: April 14, 2026
- Platform: Microsoft 365 Defender / Microsoft Sentinel
