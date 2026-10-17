# Scenario 06: LSASS Memory Dumping & Credential Access Detection

## 📌 Executive Summary
This report details an endpoint forensics investigation triggered on a primary Windows Domain Controller (DC-SRV-01). Security and Sysmon telemetry revealed an unauthorized credential access attempt where an attacker leveraged the legitimate Microsoft tool procdump.exe to target the Local Security Authority Subsystem Service (lsass.exe) memory space, aiming to dump credentials and escalate privileges across the enterprise network.

---

## 🔍 Phase 1: Event Log Triage & Telemetry Analysis
Upon analyzing Windows Security logs and advanced Sysmon telemetry during the intrusion window, critical indicators of credential dumping were isolated:

### Extracted Incident Telemetry:
| Event ID | Log Source | Source Process | Target Process / Artifact | Details / Access Rights | Risk Level |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 10 | Sysmon | procdump.exe | lsass.exe | GrantedAccess: 0x1010 (VM Read & Query) | 🔴 CRITICAL |
| 11 | Sysmon | procdump.exe | C:\Users\Admin\lsass.dmp | File Creation (Memory Dump Artifact) | 🔴 CRITICAL |
| 4688 | Windows Security | procdump.exe | N/A | CommandLine: procdump.exe -ma lsass.exe lsass.dmp | 🔴 HIGH |

> Key Observation: The attacker weaponized a legitimate administrative utility (procdump.exe) under the Living-off-the-Land (LotL) technique to evade basic static binary detection while acquiring sensitive cryptographic material from LSASS memory.

---

## 🧪 Phase 2: Payload Deconstruction & Code Intuition
Understanding how credential theft functions requires analyzing the low-level interactions between processes and operating system APIs.

### Command Structure Analysis:
procdump.exe -ma lsass.exe lsass.dmp
### Deconstruction ("Code Intuition" / فراسة الكود):
* **Targeting LSASS (lsass.exe):** LSASS holds sensitive security tokens, Kerberos tickets, and cached password hashes in RAM. Accessing its memory guarantees the attacker high-value credentials.
* **Access Mask (0x1010):** In Windows architecture, process access requires explicit permissions. The flag combination 0x1010 (PROCESS_VM_READ + PROCESS_QUERY_INFORMATION) is the definitive digital fingerprint of memory scraping tMiniDump Arguments (-ma):(-ma):** Instructs the tool to create a comprehensive memory snapshot containing all data segments of the target process, resulting in the creation of lsass.dmp.

---

## 🛡️ Phase 3: Incident Response & Remediation (NIST Framework)

To immediately neutralize the credential theft threat, a structured response was executed:

### 1. Host-Level EradicProcess Termination:ation:** Forcefully terminated the active procdump.exe process Artifact Removal:moval:** Securely deleted the generated memory dump file (lsass.dmp) to prevent exfiltration.

### 2. Post-Remediation Hardening
* RunAsPPL (Protected Process Light)Light)** for LSASS via Group Policy and Registry controls to prevent unauthorized memory read access entirely.
* Implemented strict application control and blocklists against administrative dumping utilities.

---

## 🎯 Phase 4: Behavioral Detection Engineering

To proactively detect LSASS memory dumping across enterprise environments, detection rules were established.

### 1. Splunk SPL Query (LSASS Access Detection)
index=windows EventCode=10 TargetImage="*\\lsass.exe" 
| eval access_mask=case(GrantedAccess="0x1010", "VM_READ + Query (High Risk)", 1=1, "Other Access")
| table _time, ComputerName, SourceImage, TargetImage, GrantedAccess, access_mask
| where access_mask!="Other Access"
### 2. Sigma Rule Concept (YAML)
`yaml
title: LSASS Memory Dump via Procdump or Tooling
id: d45e812b-77f9-4b1a-9f5b-111111110006
status: experimental
description: Detects process access to lsass.exe with read permissions indicative of credential dumping.
references:
  - https://github.com/AHMAD9ALKASAB/SOC-Incident-Reports
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: '0x1010'
  condition: selection
falsepositives:
  - Legitimate security scanners or EDR software (requires whitelisting verified paths)
level: high
tags:
  - attack.credential_access
  - attack.t1003.001
---

## 💡 Philosophy: "Code Intuition" (فراسة الكود)
Protecting the core identity store of an operating system requires looking beyond process names. Because attackers abuse trusted utilities like Procdump, detection engineers must rely on behavioral telemetry (Sysmon Event ID 10 and Access Masks) rather than simple file hashes to catch credential theft in real-time.
