# Scenario 07: Lateral Movement & Suspicious SMB Traffic Analysis

## 📌 Executive Summary
This report details an internal endpoint forensics and network triage investigation on workstation 10.0.2.20. Incident detection mechanisms triggered an alert for anomalous internal Lateral Movement over Server Message Block (SMB / Port 4445/445) targeting an internal database host (10.0.2.50). The attacker abused SMB named pipes and administrative file shares (C$) to stage executable binaries across the internal network segment.

---

## 🔍 Phase 1: Traffic Triage & Telemetry Correlation
Network captures and Sysmon telemetry were correlated to map the internal pivoting attempt from the compromised host (10.0.2.20) to the target host (10.0.2.50).

### Extracted Incident Telemetry:
| Event Source | Event ID / Protocol | Source IP / Process | Destination IP / Target | Details / Action | Risk Level |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Sysmon | Event ID 3 (Network Connect) | 10.0.2.20 (cmd.exe) | 10.0.2.50:445 | Outbound SMB Connection Established | 🔴 HIGH |
| Sysmon | Event ID 11 (File Create) | PSEXESVC.exe | 10.0.2.50 (C$\Windows\psexec.exe) | Remote Payload Staging via Administrative Share | 🔴 CRITICAL |
| Security | Event ID 5140 | 10.0.2.20 | \\10.0.2.50\C$ | Network Share Object Accessed | 🔴 HIGH |

> Key Observation: The attacker leveraged default administrative shares (C$) over SMB Port 445 to drop execution payloads remotely, mimicking legitimate system administration tools (PsExec) to evade standard network edge perimeter controls.

---

## 🧪 Phase 2: Payload Deconstruction & Code Intuition

Analyzing internal lateral movement requires understanding how Windows administrative tools interact with network shares and service managers.

### Lateral Movement Execution Pattern:
psexec.exe \\10.0.2.50 -u admin -p Secret123! -s cmd.exe
### Deconstruction ("Code Intuition" / فراسة الكود):
* SMB Transport (Port 445): PsExec connects to the target machine's SMB share (Admin$ or C$) to upload a temporary service binary (PSEXESVC.exe).
* Service Control Manager (SCM): The source machine uses Remote Procedure Call (RPC) over SMB to instruct the target host's SCM to register and start PSEXESVC.exe as an interactive NT AUTHORITY\SYSTEM service.
* Pivoting Strategy: By compromising host 10.0.2.20, the attacker bypasses external firewall perimeters, abusing trusted internal network channels (Port 445) to compromise high-value targets internally.

---

## 🛡️ Phase 3: Incident Response & Mitigation (NIST Framework)

To immediately neutralize the internal infection sweep and isolate the attack vector:

### 1. Host & Network Isolation
* Host Isolation: Network-isolated the compromised pivot host (10.0.2.20) to prevent further subnet discovery scans.
* SMB Access Restrictions: Applied micro-segmentation firewalls blocking workstation-to-workstation SMB (Port 445) traffic.

### 2. Remediation & Hardening
* Disabled default administrative shares (C$, Admin$) on non-server endpoint baselines where not strictly required.
* Enforced Local Account Token Filter Policy to prevent local administrative credentials from gaining full token elevation over SMB connections.

---

## 🎯 Phase 4: Behavioral Detection Engineering

To catch unauthorized internal SMB file staging and lateral movement attempts across enterprise environments:

### 1. Splunk SPL Query (Workstation-to-Workstation SMB Anomalies)
index=network_traffic dest_port=445 src_ip="10.0.2.*" dest_ip="10.0.2.*"
| stats count, values(app) as application by src_ip, dest_ip
| where src_ip != dest_ip
| eval threat_indicator="Potential Internal Lateral Movement via SMB"
| table src_ip, dest_ip, count, application, threat_indicator

### 2. Sigma Rule Concept (YAML)
`yaml
title: Internal Lateral Movement via Suspicious SMB Share Access
id: d45e812b-77f9-4b1a-9f5b-111111110007
status: experimental
description: Detects outbound SMB connections targeting administrative shares (C$, Admin$) initiated between endpoint workstations.
references:
  - https://github.com/AHMAD9ALKASAB/SOC-Incident-Reports
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5140
    ShareName|contains:
      - 'C$'
      - 'ADMIN$'
  filter_servers:
    SourceAddress|startswith: '10.0.1.' # Exclusion for management server range
  condition: selection and not filter_servers
falsepositives:
  - Domain administrative deployment tools or SCCM software updates
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.002
---

## 💡 Philosophy: "Code Intuition" (فراسة الكود)
Lateral movement relies on exploiting trusted internal channels. Detecting SMB-based attacks requires monitoring internal host-to-host communications and administrative share accesses (`C$`), identifying abnormal endpoint behaviors before attackers establish permanent footholds on critical infrastructure.
