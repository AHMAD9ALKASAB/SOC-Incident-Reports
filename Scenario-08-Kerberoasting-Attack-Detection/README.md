# Scenario 08: Kerberoasting Attack & Active Directory Identity Forensics

## 📌 Executive Summary
This report details an Active Directory (AD) security incident on a primary Domain Controller (DC-SRV-01). Security event telemetry flagged a high-volume request for Kerberos service tickets (TGS) targeting a high-privilege service account (SQL-ServiceAccount) using weak RC4 encryption (0x17), indicative of a classic Kerberoasting attack aiming at offline brute-forcing and credential harvesting.

---

## 🔍 Phase 1: Event Log Triage & Telemetry Analysis
Upon analyzing the Domain Controller's Windows Security Event Logs during the incident window, suspicious authentication requests were isolated:

### Extracted Incident Telemetry:
| Event ID | Log Source | Account Name (Client) | Service Name / Principal | Ticket Encryption Type | Client Address | Risk Level |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 4769 | Windows Security | j.doe@domain.local | SQL-ServiceAccount | 0x17 (RC4-HMAC) | 10.0.2.35 | 🔴 HIGH |
| 4769 | Windows Security | j.doe@domain.local | IIS-AppPool | 0x17 (RC4-HMAC) | 10.0.2.35 | 🔴 HIGH |
| 4769 | Windows Security | j.doe@domain.local | MSSQLSvc/db01.domain.local | 0x17 (RC4-HMAC) | 10.0.2.35 | 🔴 HIGH |

> Key Observation: A standard domain user (j.doe) systematically requested multiple Service Granting Tickets (TGS) for critical service accounts using weak RC4 encryption, bypassing modern AES standards to facilitate offline password cracking.

---

## 🧪 Phase 2: Payload Deconstruction & Code Intuition
Understanding Kerberoasting requires analyzing how Active Directory service authentication works and how adversaries exploit its core design.

### Attack Vector Mechanism:
* The AD Protocol Design: Any authenticated domain user can request a TGS ticket for *any* service registered with a Service Principal Name (SPN) in the domain.
* The Cryptographic Flaw: The requested ticket is partially encrypted using the target service account's password hash. 
* Offline Brute-Forcing: Attackers extract this ticket and use offline cracking tools (e.g., Hashcat/Rubeus) to guess the password without generating network noise or triggering account lockout policies on the DC.
* **Encryption Downgrade (0x17):** Forcing or requesting RC4-HMAC (0x17) makes the offline cracking phase significantly faster compared to AES-256 (0x12 / 0x11).

---

## 🛡️ Phase 3: Incident Response & Mitigation (NIST Framework)

To immediately contain the identity compromise and harden the Active Directory environment:

### 1. Containment & RemediatioCredential Rotation:n:** Immediately forced a password reset (complex, 25+ characters) for all targeted service accounts (SQL-ServiceAccount) to invalidate existing stolen ticketsSession Termination:n:** Purged active Kerberos sessions for the compromised service principals.

### 2. Hardening & Long-term Defense
* ImplemenAES Encryption Enforceded** policies, disabling weak RC4 encryption for Kerberos where feasible.
* Migrated standard service accountsGroup Managed Service Accounts (gMSA)A)**, which automatically manage complex passwords and rotate them regularly.

---

## 🎯 Phase 4: Behavioral Detection Engineering

To proactively detect Kerberoasting activities across enterprise environments:

### 1. Splunk SPL Query (High-Volume TGS Requests with RC4)
index=windows EventCode=4769 TicketEncryptionType="0x17" 
| stats count, values(ServiceName) as RequestedServices by AccountName, ClientAddress
| where count > 5
| eval threat_indicator="Potential Kerberoasting Activity (High RC4 Volume)"
| table AccountName, ClientAddress, count, RequestedServices, threat_indicator
### 2. Sigma Rule Concept (YAML)
`yaml
title: Kerberoasting Attack via RC4 Ticket Requests
id: d45e812b-77f9-4b1a-9f5b-111111110008
status: experimental
description: Detects multiple Kerberos service ticket requests using RC4 encryption from a single user account, indicating potential Kerberoasting.
references:
  - https://github.com/AHMAD9ALKASAB/SOC-Incident-Reports
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  filter_accounts:
    AccountName|contains:
      - '$' # Exclude computer accounts
  condition: selection and not filter_accounts
falsepositives:
  - Legacy applications or outdated scanners relying strictly on RC4
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
---

## 💡 Philosophy: "Code Intuition" (فراسة الكود)
Protecting enterprise identity stores requires looking beyond perimeter firewalls. In Active Directory, attackers do not need malware; they abuse legitimate protocol features. Defenders must monitor Kerberos ticket request volumes, encryption types, and service account configurations to catch identity-based theft early.
