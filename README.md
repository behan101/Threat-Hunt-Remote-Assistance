<img width="1200" height="725" alt="Remote Threat" src="https://drive.google.com/file/d/1skzeaDsuKP_yyBES-14g6SDBIiiDex-F/view?usp=sharing" />

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

## Platforms and Tools

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
| 1 | Flag 0: Starting Point – Suspicious Processes Spawning in Downloads | `gab-intern-vm` was the first targeted machine |
| 2 | Initial Execution Detection | Timestamp: `` |
| 3 | Quick Data Probe | RemoteURL: `` |
| 4 | Host Context Recon | TaskName: `` |
| 5 | Storage Surface Mapping | Registry Key: `` |
| 6 | Connectivity & Name Resolution Check | `` |
| 7 | Interactive Session Discovery | `` |
| 8 | Runtime Application Inventory | Next device: `` |
| 9 | Privilege Surface Check | File: `` |
| 10 | Proof-of-Access & Egress Validation | Registry value referencing: `` |
| 11 | Bundling / Staging Artifacts | RemoteURL: `` |
| 12 | Outbound Transfer Attempt (Simulated) | Script: `` |
| 13 | Scheduled Re-Execution Persistence | File: `` |
| 14 | Autorun Fallback Persistence | File: `` |
| 15 | Planted Narrative / Cover Artifact | Archive: `` |

---
### Flag 0: Starting Point - Suspicious Processes Spawning in Downloads

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
