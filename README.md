<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/bf6d8a1e-255c-40b8-ba72-784f0651a8f4" />


# 📚 Table of Contents

- [Threat Hunt: "Remote Assistance"](##-🕵️‍♂️-threat-hunt-remote-assistance)
- [Platforms and Tools](#-platforms-and-tools)
- [Summary of Findings (Flags)](#-summary-of-findings-flags)
  - [Flag 0: Starting Point – Suspicious Processes Spawning in Downloads](#)
  - [Flag 1: Initial Execution Detection](#)
  - [Flag 2: Defense Disabling](#)
  - [Flag 3: Quick Data Probe](#)
  - [Flag 4: Host Context Recon](#)
  - [Flag 5: Storage Surface Mapping](#)
  - [Flag 6: Connectivity & Name Resolution Check](#)
  - [Flag 7: Interactive Session Discovery](#)
  - [Flag 8: Runtime Application Inventory](#)
  - [Flag 9: Privilege Surface Check](#)
  - [Flag 10: Proof-of-Access & Egress Validation](#)
  - [Flag 11: Bundling / Staging Artifacts](#)
  - [Flag 12: Outbound Transfer Attempt (Simulated)](#)
  - [Flag 13: Scheduled Re-Execution Persistence](#)
  - [Flag 14: Autorun Fallback Persistence](#)
  - [Flag 15: Planted Narrative / Cover Artifact](#)
- [MITRE ATT&CK Technique Mapping](#-mitre-attck-technique-mapping)
- [Conclusion](#-conclusion)
- [Lessons Learned](#-lessons-learned)
- [Recommendations for Remediation](#-recommendations-for-remediation)

---

# 🕵️‍♂️ Threat Hunt: *"Remote Assistance"*

## Scenario

> *"A routine support request should have ended with a reset and reassurance. Instead, the so-called “help”
left behind a trail of anomalies that don’t add up."*

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging,
leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold,
then expanding reach, then preparing to linger long after the session ended.
And just when the activity should have raised questions, a neat explanation appeared — a story planted in
plain sight, designed to justify the very behavior that demanded scrutiny.
This wasn’t remote assistance. It was a misdirection.
Your mission this time is to reconstruct the timeline, connect the scattered remnants of this “support
session”, and decide what was legitimate, and what was staged.
The evidence is here. The question is whether you’ll see through the story or believe it.

This report includes:

- 📅 Timeline reconstruction of auditing, reconnaissance, and attempted exfiltration of data on the device **`gab-intern-vm`**
- 📜 Detailed queries using Microsoft Defender Advanced Hunting (KQL)
- 🧠 MITRE ATT&CK mapping to understand TTP alignment
- 🧪 Evidence-based summaries supporting each flag and behavior discovered


---

## 🧰 Platforms and Tools

**Analysis Environment:**
- Microsoft Defender for Endpoint
- Log Analytics Workspace
- Azure

**Techniques Used:**
- Kusto Query Language (KQL)
- Behavioral analysis of endpoint logs (DeviceProcessEvents, DeviceNetworkEvents, DeviceRegistryEvents)

---

## Summary of Findings (Flags)

| Flag | Objective Description | Finding |
|------|------------------------|---------|
| 0 | Starting Point – Suspicious Processes Spawning in Downloads | `gab-intern-vm` was the first targeted machine |
| 1 | Initial Execution Detection |  |
| 2 | Defense Disabling |  |
| 3 | Quick Data Probe |   |
| 4 | Host Context Recon |   |
| 5 | Storage Surface Mapping |  |
| 6 | Connectivity & Name Resolution Check |  |
| 7 | Interactive Session Discovery |  |
| 8 | Runtime Application Inventory |  |
| 9 | Privilege Surface Check |  |
| 10 | Proof-of-Access & Egress Validation |  |
| 11 | Bundling / Staging Artifacts |  |
| 12 | Outbound Transfer Attempt (Simulated) |  |
| 13 | Scheduled Re-Execution Persistence |  |
| 14 | Autorun Fallback Persistence |  |
| 15 | Planted Narrative / Cover Artifact |  |

---
### 🚩 Flag 0: Starting Point - Suspicious Processes Spawning in Downloads

**Objective:**
Determine where to start hunting with the following intel:
1. Multiple machines in the department started spawning processes originating from the download folders.
This unexpected scenario occurred during the first half of October.
2. Several machines were found to share the same types of files — similar executables, naming patterns,
and other traits.
3. Common keywords among the discovered files included “desk,” “help,” “support,” and “tool.”
4. Intern operated machines seem to be affected to certain degree.

**Flag Value:**
`gab-intern-vm`

**Detection Strategy:**
Multiple alerts were issued indicating that multiple machines were spawning processes originating from the 'download' folders around the first half of October (10/01/2025 - 10/15/2025). Common keywords among the discovered files included "desk", "help", "support", and "tool". The following query was used in Microsoft Defender to find any files associated with the keywords:

**KQLQuery:**
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FileName matches regex @"(?i)(desk|help|support|tool)"
| where FolderPath has @"\Downloads\"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1, InitiatingProcessAccountName
| order by Timestamp desc
```
**Evidence:**

<img width="1902" height="359" alt="image" src="https://github.com/user-attachments/assets/12e8effd-bd58-40e4-9d45-8d1fc05ac0db" />

The initial query showed suspicious files that were downloaded with the keywords in the alert. The affected device was identified as `gab-intern-vm`.

**Why This Matters:**
The query allowed us to narrow down the affected machines that may be responsible for the alert.

### 🚩 Flag 1: Initial Execution Detection
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 2: Defense Disabling
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 3: Quick Data Probe
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 4: Host Context Recon
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 5: Storage Surface Mapping
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 6: Connectivity & Name Resolution Check
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 7: Interactive Session Discovery
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 8: Runtime Application Inventory
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 9: Privilege Surface Check
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 10: Proof-of-Access & Egress Validation
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 11: Bundling / Staging Artifacts
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 12: Outbound Transfer Attempt (Simulated)
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 13: Scheduled Re-Execution Persistence
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 14: Autorun Fallback Persistence
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

### 🚩 Flag 15: Planted Narrative / Cover Artifact
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**

