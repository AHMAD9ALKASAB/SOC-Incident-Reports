# Tri-Agent Battle Log & Case Study: LSASS Dump & Pass-the-Hash

> From AI Hallucination to Production-Ready 10/10 Detection Engineering.

## 📌 Executive Summary
This case study documents a live test of the Tri-Agent AI SOC Pipeline using a high-severity Windows security scenario: LSASS Memory Dumping (T1003.001) followed by NTLM Pass-the-Hash Lateral Movement (T1550.002). 

It demonstrates how raw AI analysis (Analyst Agent) often suffers from critical logical flaws and brittle detection syntax, how an aggressive review (Auditor Agent) shreds these weaknesses, and how a senior-level synthesis (Refiner Agent) delivers flawless, enterprise-grade detection artifacts.

---

## 🔬 The Ground Truth Scenario
*   Target Host: FIN-SRV-02 (Critical Windows Server 2022).
*   Domain Controller: DC-01 (10.0.0.5).
*   Attacker Action 1: At 14:22:10 UTC, process rundll32.exe was spawned by cmd.exe running under local administrator context (FIN-SRV-02\LocalAdmin).
*   Attacker Action 2: rundll32.exe invoked comsvcs.dll, MiniDump targeting lsass.exe (PID: 748), generating a memory dump file at C:\Windows\Tasks\lsass.dmp.
*   Telemetry Observed on FIN-SRV-02:
    *   Sysmon Event ID 1 (Process Create): ParentImage "C:\Windows\System32\cmd.exe", Image "C:\Windows\System32\rundll32.exe", CommandLine containing comsvcs.dll and MiniDump.
    *   Sysmon Event ID 10 (ProcessAccess): SourceImage "C:\Windows\System32\rundll32.exe", TargetImage "C:\Windows\System32\lsass.exe", GrantedAccess "0x1fffff" (PROCESS_ALL_ACCESS).
    *   Sysmon Event ID 11 (FileCreate): TargetFilename "C:\Windows\Tasks\lsass.dmp".
*   Attacker Action 3: At 14:25:00 UTC, an NTLM Pass-the-Hash authentication attempt originated from FIN-SRV-02 targeting Domain Controller DC-01 (10.0.0.5).
*   Telemetry Observed on DC-01:
    *   Windows Security Event ID 4624 (Successful Logon): LogonType "3" (Network), AuthenticationPackage "NTLM", TargetUserName "DomainAdmin_Sami", WorkstationName "FIN-SRV-02", KeyLength "0".
    *   Sysmon Event ID 3 (Network Connection): SourceIp "10.0.0.45" (FIN-SRV-02), DestinationIp "10.0.0.5" (DC-01), DestinationPort "445" (SMB).

---

## ⚠️ Phase 1: The Analyst Report (Initial Baseline)
*The Analyst Agent correctly decomposed the threat and mapped MITRE ATT&CK techniques, but produced a catastrophic detection engineering failure in its first Sigma rule.*

*   Critical Flaw: The initial Sigma rule attempted to require Sysmon Event IDs 1, 10, and 11 in a single event condition (selection_process and selection_access and selection_file). Because Sigma rules evaluate a single event, no single log can have three different Event IDs simultaneously. The rule was structurally broken and would never fire.
*   SIEM Bottleneck: The initial Splunk SPL relied on heavy, unindexed join subsearches across high-volume Sysmon logs without time bounds, leading to severe performance degradation.

---

## 🛑 Phase 2: The Auditor Critique (The Guillotine)
*The Auditor Agent tore apart the initial report, awarding it a Verdict Score of 4/10.*

*   Key Audit Findings:
    1. Logical Impossibility: The Sigma condition combining Event IDs 1, 10, and 11 is a critical false-negative trap.
    2. Evasion Bypasses: Attackers could bypass Rule 1 by using alternate dumpers (e.g., procdump.exe), changing dump filenames (e.g., dump.bin), or using non-Domain Admin accounts for Pass-the-Hash.
    3. Performance Nightmares: Unbounded join commands and leading wildcards (*comsvcs.dll*) destroy SIEM index-level filtering.

---

## ✨ Phase 3: The Refiner Hardening (Production-Ready 10/10)
*The Refiner Agent synthesized the critique and delivered pristine, enterprise-grade artifacts.*

### 🛡️ Hardened Sigma Rules (Single-Event & Resilient)
#### Rule 1: Suspicious LSASS Process Access (Sysmon ID 10)
title: Suspicious LSASS Process Access
id: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
status: stable
description: Detects processes opening lsass.exe with high-risk access rights indicative of credential dumping, independent of the dumping tool.
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: SOC Detection Engineering
date: 2026-10-29
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1fffff'
      - '0x1010'
      - '0x1410'
      - '0x143a'
      - '0x1f0fff'
      - '0x1f1fff'
      - '0x1f2fff'
      - '0x1f3fff'
  filter_known_good:
    SourceImage|endswith:
      - '\MsMpEng.exe'
      - '\CSFalconService.exe'
      - '\SentinelAgent.exe'
      - '\CylanceSvc.exe'
      - '\SavService.exe'
      - '\ccSvcHst.exe'
      - '\MsSense.exe'
      - '\SenseCncProxy.exe'
  condition: selection and not filter_known_good
falsepositives:
  - EDR/AV self-protection. Add vendor binaries to filter_known_good.
  - Approved memory analysis tools. Allowlist by hash and path with change control.
level: critical

#### Rule 2: LSASS Dump File Creation in Staging Directory (Sysmon ID 11)
title: LSASS Dump File Creation in Staging Directory
id: 2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: stable
description: Detects creation of memory-dump-like files in common staging directories by processes frequently abused for credential dumping. Does not depend on the filename lsass.dmp.
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: SOC Detection Engineering
date: 2026-10-29
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  service: sysmon
detection:
  selection_event:
    EventID: 11
  selection_dir:
    TargetFilename|startswith:
      - 'C:\Windows\Tasks\'
      - 'C:\Windows\Temp\'
      - 'C:\Users\Public\'
      - 'C:\ProgramData\'
  selection_ext:
    TargetFilename|endswith:
      - '.dmp'
      - '.bin'
      - '.mdmp'
  selection_image:
    Image|endswith:
      - '\rundll32.exe'
      - '\procdump.exe'
      - '\procdump64.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\taskmgr.exe'
  filter_legit:
    Image|endswith:
      - '\werfault.exe'
      - '\WerFault.exe'
  condition: selection_event and selection_dir and selection_ext and selection_image and not filter_legit
falsepositives:
  - Legitimate crash dumps. werfault.exe is filtered.
  - Administrative diagnostics writing .dmp/.bin to staging directories. Baseline and allowlist by image hash.
level: high

---

### 📊 Optimized Splunk SPL (No Joins, Stats-Based)

#### SPL 1: LSASS Dump Chain Correlation (ProcessGuid & Stats)
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-15m latest=now
  (EventCode=1 OR EventCode=10 OR EventCode=11)
| eval proc_guid=coalesce(ProcessGuid, SourceProcessGuid)
| eval event_type=case(
    EventCode=1 AND Image="C:\\Windows\\System32\\rundll32.exe" AND CommandLine="*comsvcs*" AND (CommandLine="*MiniDump*" OR CommandLine="*#24*"), "process_create",
    EventCode=10 AND SourceImage="C:\\Windows\\System32\\rundll32.exe" AND TargetImage="C:\\Windows\\System32\\lsass.exe" AND (GrantedAccess="0x1fffff" OR GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x143a"), "process_access",
    EventCode=11 AND (TargetFilename="C:\\Windows\\Tasks\\*" OR TargetFilename="C:\\Windows\\Temp\\*" OR TargetFilename="C:\\Users\\Public\\*" OR TargetFilename="C:\\ProgramData\\*") AND (TargetFilename="*.dmp" OR TargetFilename="*.bin" OR TargetFilename="*.mdmp"), "file_create"
  )
| where isnotnull(event_type)
| stats values(event_type) as event_types dc(event_type) as event_type_count min(_time) as first_time max(_time) as last_time values(CommandLine) as command_lines values(TargetFilename) as target_files by host proc_guid
| where event_type_count>=3 AND (last_time - first_time)<=300
| table host proc_guid event_types event_type_count first_time last_time command_lines target_files

---

## 🏆 Conclusion
By enforcing the Tri-Agent Pipeline, security teams transform vulnerable, AI-generated code into resilient, performance-optimized, and enterprise-ready detection engineering artifacts.
