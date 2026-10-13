# Scenario 05: Windows Persistence & Sysmon Event Analysis (Scheduled Tasks)

## 📌 Executive Summary
This report details an endpoint forensics investigation triggered on an internal finance server (FIN-SRV-01). Security event logs and Sysmon telemetry revealed a classic post-exploitation Persistence technique: an attacker leveraging legitimate Windows binaries (schtasks.exe) to spawn encoded PowerShell commands as NT AUTHORITY\SYSTEM on an hourly recurring schedule.

---

## 🔍 Phase 1: Event Log Triage & Telemetry Analysis
Upon analyzing Windows Security logs and advanced Sysmon telemetry during the incident window, key artifacts were extracted:

### Extracted Incident Telemetry:
| Event ID | Log Source | Process / Details | Account Privilege | Risk Level |
| :--- | :--- | :--- | :--- | :--- |
| 4688 | Windows Security | schtasks.exe /Create /TN "UpdateCheck" /TR "powershell.exe -e aW52b2tl..." /SC HOURLY | Administrator | 🔴 HIGH |
| 1 | Sysmon | Process Creation: schtasks.exe (Parent: cmd.exe) | SYSTEM | 🔴 HIGH |
| 106 | TaskScheduler | Scheduled Task Registered: "\UpdateCheck" | NT AUTHORITY\SYSTEM | 🔴 CRITICAL |

> Key Observation: The attacker disguised the persistence mechanism under a benign task name (UpdateCheck) to evade casual administrative review, executing obfuscated PowerShell payloads at fixed hourly intervals with maximum system privileges.

---

## 🧪 Phase 2: Payload Deconstruction & Code Intuition
The core component of this persistence mechanism relied on obfuscating the malicious execution payload using Base64 encoding.

### Command Structure Analysis:
schtasks.exe /Create /TN "UpdateCheck" /TR "powershell.exe -e aW52b2tlLWV4cHJlc3Npb24..." /SC HOURLY
### Deconstruction ("Code Intuition" / فراسة الكود):
* Living off the Land (LotL): The attacker used built-in Windows administrative utilities (schtasks.exe) rather than dropping custom malware binaries, reducing file-based behavioral footprints.
* **Base64 Encoding (-EncodedCommand / -e):** By passing the payload in Unicode Base64 format, the attacker successfully bypassed basic static inspection rules and avoided syntax errors involving special characters inside shell argumentsPrivilege Context:t:** Executing under NT AUTHORITY\SYSTEM ensures complete administrative control across the local operating system regardless of standard user boundaries.

---

## 🛡️ Phase 3: Incident Response & Remediation (NIST Framework)

To eradicate the backdoor and restore host integrity, the following actions were executed:

### 1. Host-Level EradicatioTask Deletion:n:** Forcefully removed the malicious scheduled task using the command line:
 
  schtasks /Delete /TN "UpdateCheck" /F
  
* **Process Termination:** Terminated any active rogue PowerShell child processes spawned by the scheduler.

### 2. Post-Remediation Hardening
* Audited all registered tasks across the enterprise using automated script sweeps.
* Enforced stricter Group Policy Object (GPO) controls over PowerShell execution policies and script block logging (Event ID 4104).

---

## 🎯 Phase 4: Behavioral Detection Engineering

To proactively hunt and detect similar persistence mechanisms across the enterprise, detection rules were engineered.

### 1. Splunk SPL Query (Scheduled Task Persistence Detection)
index=windows EventCode=4688 Image="*\\schtasks.exe" CommandLine="* /Create *" 
| eval threat_indicator=case(match(CommandLine, "powershell.*-e"), "Encoded PowerShell Scheduled Task Persistence", 1=1, "Standard Scheduled Task Creation")
| table _time, ComputerName, AccountName, CommandLine, threat_indicator
### 2. Sigma Rule Concept (YAML)
`yaml
title: Suspicious Scheduled Task Creation via PowerShell Encoding
id: d45e812b-77f9-4b1a-9f5b-111111110005
status: experimental
description: Detects the creation of scheduled tasks executing encoded PowerShell payloads for persistence.
references:
  - https://github.com/AHMAD9ALKASAB/SOC-Incident-Reports
logsource:
  product: windows
  service: security
detection:
  selection_event:
    EventID: 4688
  selection_cli:
    CommandLine|contains:
      - 'schtasks'
      - '/Create'
      - 'powershell'
      - '-e'
  condition: selection_event and selection_cli
falsepositives:
  - Legitimate administrative maintenance scripts (requires baseline filtering)
level: high
`

---

## 💡 Philosophy: "Code Intuition" (فراسة الكود)
Understanding persistence requires looking past the utility (`schtasks`) to examine the command arguments and execution context. When attackers weaponize administrative tools with encoded scripting languages, detection engineers must focus on behavioral telemetry (Sysmon and process trees) rather than static file hashes.
