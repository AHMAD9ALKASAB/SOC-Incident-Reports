# Scenario 11: Microsoft Office Macro & Command Shell Spawning (VBA Stomping / Phishing)

## 📌 Executive Summary
This report investigates a targeted phishing campaign that successfully achieved initial access and execution within the finance department. An employee received a malicious Microsoft Word document (Invoice_Q4_Financial.docm). Upon opening the file and enabling macros, a hidden VBA payload executed a command-line interpreter (cmd.exe / powershell.exe) directly from the Office application process. The adversary leveraged evasion techniques (encoded commands, hidden windows) to bypass traditional EDR visibility, followed by Process Hollowing into a legitimate system process (svchost.exe) to establish a covert Command & Control (C2) channel on port 443.

## 🔍 Phase 1: Process Telemetry & Triage Analysis
Correlation of Sysmon and EDR telemetry captured during the incident window revealed the following malicious behavior. The Tier 1 triage successfully differentiated a legitimate IT script (False Positive) from a malicious encoded PowerShell execution (True Positive).

Extracted Incident Telemetry (True Positive - Alert B):

| Timestamp (UTC) | Sysmon Event ID | Parent Process | Child Process | Command Line / Details | Analysis Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-11-12 09:14:02.102 | 1 (Process Creation) | winword.exe | powershell.exe | powershell.exe -nop -w hidden -enc <base64> | True Positive: Office spawning shell (VBA Stomping). |
| 2026-11-12 09:14:03.500 | 10 (Process Access) | powershell.exe | svchost.exe | PROCESS_ALL_ACCESS | Process Hollowing / Memory Injection attempt. |
| 2026-11-12 09:14:05.100 | 3 (Network Connection) | svchost.exe | 185.199.108.153:443 | Destination Port 443 (HTTPS) | C2 beaconing immediately after execution. |

Key Observation: Legitimate Office applications rarely spawn command shells. The use of -enc (EncodedCommand) and -w hidden (Hidden Window) by the adversary confirms an attempt to bypass static string-based detections.

## 🧪 Phase 2: Protocol Deconstruction & Code Intuition
Analyzing this attack vector requires understanding the execution flow of Microsoft Office macros:

* The VBA Execution Flow: Word executes Auto_Open or Document_Open macros. The attacker uses the VBA Shell function to execute external binaries.
* Why Perimeter Defenses Fail: The .docm file is syntactically valid. Traditional AV scans for known malicious signatures. The VBA code is often obfuscated or "stomped" (modified in memory) to evade detection.
* Evasion Tactics: By launching powershell.exe with -enc, the attacker passes a Base64 encoded string that bypasses network-level signature checks. The -w hidden flag ensures the user (and some EDRs) don't see the terminal window. Finally, injecting into svchost.exe makes the C2 traffic look like legitimate Windows traffic.

## 🛡 Phase 3: Incident Response & Mitigation (NIST Framework)
To immediately restore service availability and mitigate the threat:

1. Active Containment
   * Immediate network isolation of the affected workstation (WKSTN-FIN-12) to prevent lateral movement.
   * Termination of the malicious powershell.exe process and reset of user credentials.

2. Hardening Measures
   * Enforced Group Policy (GPO) to block macros in Office documents downloaded from the internet (Mark of the Web).
   * Disabled powershell.exe for non-administrative users.

## 🎯 Phase 4: Behavioral Detection Engineering
To proactively catch this attack vector across the enterprise SIEM:

### 1. Splunk SPL Query (Anomalous Office Shell Spawning)
index=sysmon EventCode=1
| search ParentImage IN ("*\\winword.exe", "*\\excel.exe") AND Image IN ("*\\powershell.exe", "*\\cmd.exe")
| eval threat_indicator="Potential VBA Stomping - Office Spawning Shell"
| table _time, host, ParentImage, Image, CommandLine, threat_indicator
### 2. Sigma Rule (YAML) - Validated with Sigma-Intuition
Note: This rule was audited using Sigma-Intuition. The initial draft scored 40/100 (flagged for missing EVD001 coverage and PRF001 wildcards). After refining the rule to cover encoded commands, the score improved to 80/100. The remaining PRF001 is an accepted trade-off for broad coverage.

title: Microsoft Office Application Spawning Command Shell
id: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
status: experimental
description: Detects Microsoft Office applications spawning command line interpreters, which is a strong indicator of malicious macro execution or phishing payloads.
references:
    - https://attack.mitre.org/techniques/T1566/001/
    - https://attack.mitre.org/techniques/T1059/005/
author: Ahmad Alqassab (SOC Detection Engineer)
date: 2026/11/12
tags:
    - attack.t1566.001
    - attack.t1059.005
logsource:
    product: windows
    service: sysmon
detection:
    selection_parent:
        ParentImage|endswith:
            - '\winword.exe'
            - '\excel.exe'
            - '\powerpnt.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    condition: selection_parent and selection_child
falsepositives:
    - Legitimate internal administrative scripts or automated macro reporting tools.
level: high
## 💡 Philosophy: "Code Intuition" (فراسة الكود)

VBA Stomping is a psychological attack before it is a technical one; it manipulates the human element (the employee opening the invoice) to gain execution. Effective detection engineering requires looking beyond the file extension to analyze the process lineage (Parent-Child relationship). We must ask: Why is a word processor spawning a command shell? And when writing the detection rule, we must use our own tools (like Sigma-Intuition) to ensure our defenses are as flawless as the adversary's attack.
