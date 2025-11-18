<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/bf6d8a1e-255c-40b8-ba72-784f0651a8f4" />


# 📚 Table of Contents

- [Threat Hunt: "Remote Assistance"](#%EF%B8%8F%E2%80%8D%EF%B8%8F-threat-hunt-remote-assistance)
- [Platforms and Tools](#-platforms-and-tools)
- [Summary of Findings (Flags)](#-summary-of-findings-flags)
  - [Flag 0: Starting Point – Suspicious Processes Spawning in Downloads](#-flag-0-starting-point---suspicious-processes-spawning-in-downloads)
  - [Flag 1: Initial Execution Detection](#-flag-1-initial-execution-detection)
  - [Flag 2: Defense Disabling](#-flag-2-defense-disabling)
  - [Flag 3: Quick Data Probe](#-flag-3-quick-data-probe)
  - [Flag 4: Host Context Recon](#-flag-4-host-context-recon)
  - [Flag 5: Storage Surface Mapping](#-flag-5-storage-surface-mapping)
  - [Flag 6: Connectivity & Name Resolution Check](-flag-6-connectivity--name-resolution-check)
  - [Flag 7: Interactive Session Discovery](#-flag-7-interactive-session-discovery)
  - [Flag 8: Runtime Application Inventory](#-flag-8-runtime-application-inventory)
  - [Flag 9: Privilege Surface Check](#-flag-9-privilege-surface-check)
  - [Flag 10: Proof-of-Access & Egress Validation](#-flag-10-proof-of-access--egress-validation)
  - [Flag 11: Bundling / Staging Artifacts](#-flag-11-bundling--staging-artifacts)
  - [Flag 12: Outbound Transfer Attempt (Simulated)](#-flag-12-outbound-transfer-attempt-simulated)
  - [Flag 13: Scheduled Re-Execution Persistence](#-flag-13-scheduled-re-execution-persistence)
  - [Flag 14: Autorun Fallback Persistence](#-flag-14-autorun-fallback-persistence)
  - [Flag 15: Planted Narrative / Cover Artifact](#-flag-15-planted-narrative--cover-artifact)
- [MITRE ATT&CK Technique Mapping](#-mitre-attck-technique-mapping)
- [Conclusion](#-conclusion)
- [Lessons Learned](#-lessons-learned)
- [Recommendations for Remediation](#%EF%B8%8F-recommendations-for-remediation)

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
- 🎯 MITRE ATT&CK mapping to understand TTP alignment
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

## 📔 Summary of Findings (Flags)

| Flag | Objective Description | Finding | TimeStamp |
|------|------------------------|---------|-----------|
| 0 | Starting Point – Suspicious Processes Spawning in Downloads | `gab-intern-vm` was the first targeted machine | 2025-10-09T12:22:27.6514901Z |
| 1 | Initial Execution Detection | `-ExecutionPolicy` was the earliest anomalous execution | 2025-10-09T12:22:27.6514901Z |
| 2 | Defense Disabling | `DefenderTamperArtifact.lnk` was created in relation to the exploit | 2025-10-09T12:34:59.1260624Z |
| 3 | Quick Data Probe | `"powershell.exe" -NoProfile -Sta -Command` contained a `Get-Clipboard` to attempt to collect transient info  | 2025-10-09T12:50:39.955931Z |
| 4 | Host Context Recon | At `2025-10-09T12:51:44.3425653Z` the Processs Command Line `qwinsta.exe` was executed | 2025-10-09T12:51:44.3425653Z |
| 5 | Storage Surface Mapping | `"cmd.exe" /c wmic logicaldisk get name,freespace,size` query is indicative of storage surface mapping | 2025-10-09T12:51:18.3848072Z |
| 6 | Connectivity & Name Resolution Check |  |  |
| 7 | Interactive Session Discovery |  |  |
| 8 | Runtime Application Inventory |  |  |
| 9 | Privilege Surface Check |  |  |
| 10 | Proof-of-Access & Egress Validation |  |  |
| 11 | Bundling / Staging Artifacts |  |  |
| 12 | Outbound Transfer Attempt (Simulated) |  |  |
| 13 | Scheduled Re-Execution Persistence |  |  |
| 14 | Autorun Fallback Persistence |  |  |
| 15 | Planted Narrative / Cover Artifact |  |  |

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
`2025-10-09T12:22:27.6514901Z`

**Detection Strategy:**
Multiple alerts were issued indicating that multiple machines were spawning processes originating from the "downloads" folders around the first half of October (10/01/2025 - 10/15/2025). Common keywords among the discovered files included "desk", "help", "support", and "tool". The following query was used in Microsoft Defender to find any files associated with the keywords:

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

---

### 🚩 Flag 1: Initial Execution Detection

**Objective:**
Detect the earliest anomalous execution that could represent an entry point.

**Flag Value:**
`-ExecutionPolicy`
`2025-10-09T12:22:27.6514901Z`

**Detection Strategy:**
In order to find the earliest anomalous execution, the query needed to be fine-tuned to look for suspicious Command Line Interface (CLI) parameters. The suspicious file was created at `2025-10-09T12:22:27.6514901Z` and named "SupportTool.ps1". Using this time frame to narrow down results, the DeviceProcessEvents query can be adjusted accordingly.

**KQLQuery:**

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessFileName =~ "powershell.exe"
| where Timestamp between (datetime(2025-10-09T12:00:00Z) .. datetime(2025-10-09T12:30:00Z))
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Evidence:**
<img width="1699" height="220" alt="image" src="https://github.com/user-attachments/assets/2ec6d32d-6ade-4e54-b420-435c7d793d16" />

**Why This Matters:**
The first Command Line Interface Process originating from the suspicious file within the Downloads directory can lead the investigation into new paths. Collection of evidence and signs of intent will be easier to find if the parent files and processes are known.

---

### 🚩 Flag 2: Defense Disabling

**Objective:**
Identify indicators that suggest attempts to imply or simulate changing security posture.

**Flag Value:**
`DefenderTamperArtifact.lnk`
`2025-10-09T12:34:59.1260624Z`

**Detection Strategy:**
The previous results gave a timeframe of when the initial process was executed. Knowing that the possibility of any indications of attempts or changes to the security postue would be present after the timeframe of `2025-10-09T12:22:27.6514901Z`, the query was adjusted to after the known initial process. Any file creation, modifications, or copies would be scrutinized for any alarming behaviors.

**KQLQuery:**

```kql
DeviceFileEvents
| where Timestamp between (datetime('2025-10-09T12:22:27.6588913Z') .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| where ActionType in ("FileCreated","FileModified","FileCopied")
| order by Timestamp asc
```

**Evidence:**
<img width="2083" height="492" alt="image" src="https://github.com/user-attachments/assets/be7574d0-f065-4af1-827f-0238510a9877" />

**Why This Matters:**
An artifact creation or short-lived process that contains tamper-related contents found to be related to the exploit can indicate intent of changing mitigation. The file 'DefenderTamperArtifact.lnk' is proof of intent.

---

### 🚩 Flag 3: Quick Data Probe

**Objective:**
Spot brief, opportunistic checks for readily available sensitive content.

**Flag Value:**
`"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`
`2025-10-09T12:50:39.955931Z`

**Detection Strategy:**
Attackers often look for low effort wins first. Quick probes such as these can often precede broader reconnaissance. Adjustments should be made to search for transient data such as anything related to "clip" or "clipboard".

**KQLQuery:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("clip.exe","Get-Clipboard","Set-Clipboard","Out-Clipboard"," | clip")
| summarize count() by ProcessCommandLine, DeviceName, InitiatingProcessFileName
```

**Evidence:**
<img width="1217" height="218" alt="image" src="https://github.com/user-attachments/assets/310def0c-c35c-4bfb-97ac-e7a596e80949" />

**Why This Matters:**
The attempts at probing for readily available sensitive content such as the "clipboard" can show evidence for intent for opportunistic checks.

---

### 🚩 Flag 4: Host Context Recon

**Objective:**
Find activity that gathers basic host and user context to inform follow-up actions.

**Flag Value:**
`2025-10-09T12:51:44.3425653Z`

**Detection Strategy:**
Activity related to queries for context and reconnaissance shape attack decisions such as "who", "what", and "where" to target objectives. By looking for Proccess Command Line inputs for typical host recon commands such as "whoami", "systeminfo", "ipconfig", "query user", "quser", "qwinsta", etc, the proof for recon can be obtained.

**KQLQuery:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("whoami", "hostname", "systeminfo", "ipconfig", "ipconfig /all", "net user", "net localgroup", "query user", "quser", "qwinsta", "wmic", "Get-ComputerInfo", "Get-CimInstance",
 "Get-WmiObject", "Get-NetIPConfiguration", "Get-NetAdapter", "Get-NetIPAddress", "Get-Process", "tasklist", "netstat -ano", "reg query", "Get-Service", "Get-LocalUser", "Get-ChildItem Env:")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp desc
```
**Evidence:**
<img width="1266" height="251" alt="image" src="https://github.com/user-attachments/assets/8dbc8e44-3926-4959-940f-deb8e14ae564" />

**Why This Matters:**
Attempts that try to identify information about the host can be observed as reconnaissance and treated collected as evidence. The attacker has shown interest in discovering information about the host which can lead to attempts are understanding the scope or attack surface.

---

### 🚩 Flag 5: Storage Surface Mapping

**Objective:**
Detect discovery of local or network storage locations that might hold interesting data.

**Flag Value:**
`"cmd.exe" /c wmic logicaldisk get name,freespace,size`
`2025-10-09T12:51:18.3848072Z`

**Detection Strategy:**
Any enumeration of filesystem, share surfaces, and lightweight checks of available storaged would indicate attempts for storage surface mapping. Searching for any ProcessCommandLine and quick "read-only" commands such as "net view", "dir", "Get-PSDrive", "wmic logicaldisk" with connections to network share queries like "net view \\HOST” or “Get-SmbShare" would show explicit network share discovery.

**KQLQuery:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ( "Get-ChildItem","Get-PSDrive","Get-Volume","Get-SmbShare","Get-SmbMapping", "net view","net share","net use","dir ","wmic logicaldisk","fsutil volume diskfree", "mountvol","robocopy /L")
| order by DeviceName asc, Timestamp asc
| project DeviceName, Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
```

**Evidence:**
<img width="1378" height="279" alt="image" src="https://github.com/user-attachments/assets/bcdf7a3b-4d3b-45dd-9d9e-51dd9e5bfb16" />

**Why This Matters:**
In this instance, a query for the disk name, available space, and total volume size shows intent to assess the storage information on the host device which further supports intent for surface mapping.

---

### 🚩 Flag 6: Connectivity & Name Resolution Check
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 7: Interactive Session Discovery
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 8: Runtime Application Inventory
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 9: Privilege Surface Check
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 10: Proof-of-Access & Egress Validation
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 11: Bundling / Staging Artifacts
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 12: Outbound Transfer Attempt (Simulated)
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 13: Scheduled Re-Execution Persistence
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 14: Autorun Fallback Persistence
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

### 🚩 Flag 15: Planted Narrative / Cover Artifact
**Objective:**
**Flag Value:**
**Detection Strategy:**
**KQLQuery:**
```kql
```
**Evidence:**
**Why This Matters:**

---

## 🎯 MITRE ATT&CK Technique Mapping

| Flag | MITRE Technique                    | ID                                                          | Description                                                             |
| ---- | ---------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------- |
| 0    | PowerShell                         |                                                             |                                                                         |
| 1    | Application Layer Protocol         |                                                             |                                                                         |
| 2    | Registry Run Keys/Startup Folder   |                                                             |                                                                         |
| 3    | Scheduled Task/Job                 |                                                             |                                                                         |
| 4    | Obfuscated Files or Information    |                                                             |                                                                         |
| 5    | Indicator Removal on Host          |                                                             |                                                                         |
| 6    | Remote Services: Scheduled Task    |                                                             |                                                                         |
| 7    | Lateral Tool Transfer              |                                                             |                                                                         |
| 8    | Registry Modification              |                                                             |                                                                         |
| 9    | Application Layer Protocol         |                                                             |                                                                         |
| 10   | WMI Event Subscription             |                                                             |                                                                         |
| 11   | Credential Dumping Simulation      |                                                             |                                                                         |
| 12   | Data Staged: Local                 |                                                             |                                                                         |
| 13   | Data from Information Repositories |                                                             |                                                                         |
| 14   | Archive Collected Data             |                                                             |                                                                         |
| 15   | Ingress Tool Transfer              |                                                             |                                                                         |

---

## 🧾 Conclusion


---

## 🎓 Lessons Learned


---

## 🛠️ Recommendations for Remediation


