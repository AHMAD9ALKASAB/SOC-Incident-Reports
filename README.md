# 🛡️ SOC Incident Report: Kerberos Password Spraying Detection

## 📌 Executive Summary
During a routine Threat Hunting session, multiple Kerberos authentication failure events (EventCode 4771) were detected via Splunk SIEM. Further investigation confirmed an automated Password Spraying Attack originating from an internal host targeting critical domain accounts.

* Alert Source: SIEM Log Analysis / Threat Hunting Routine
* Severity Level: 🟠 MEDIUM (High Potential Impact on Domain Controller)
* Incident Status: Closed / Mitigated

---

## 🔍 Investigation & Technical Analysis

* Threat Type: Credential Access / Password Spraying (MITRE ATT&CK T1110.003)
* Target Protocol: Kerberos (Pre-Authentication)
* Event ID: 4771 (Kerberos pre-authentication failed)
* Attacker IP Address: 172.16.66.1
* Target Domain: THREEBEESCO.COM
* Targeted Accounts: Administrator, backdoor
* Impact Assessment: No evidence of successful authentication (EventCode 4768 / 4624) was found following the failure events. No domain accounts were compromised.

### 📅 Attack Timeline
| Timestamp (UTC) | Source IP | Event ID | Action / Observation |
| :--- | :--- | :--- | :--- |
| 2020-07-22 23:29:36 | 172.16.66.1 | 4771 | Pre-auth failed for user Administrator (Port 55967) |
| 2020-07-22 23:29:36 | 172.16.66.1 | 4771 | Pre-auth failed for user backdoor (Port 55968) |
| 2020-07-22 23:35:00 | Internal SOC | N/A | Analysis initiated; IP isolated at network level |

### 💡 Key Technical Findings
1. Attack Pattern: Rapid sequential authentication failures across multiple accounts within the same second (23:29:36), utilizing sequential source ports (55967, 55968).
2. Parsing Challenge: Raw log fields were unstructured in the default parsing view. Custom Regex (rex) was crafted to parse and isolate Client Address and Account Name dynamically.

---

## 🛠️ Detection Query (Splunk SPL)

index=* EventCode=4771 | rex "Account Name:\s+(?<user>\S+)" | rex "Client Address:\s+(?<ip>\S+)" | stats count by ip, user

---

## 🚨 Mitigation & Actionable Recommendations

1. Containment: Immediately block and isolate IP 172.16.66.1 at the internal firewall/switch level.
2. Account Hardening: Enforce Multi-Factor Authentication (MFA) and reset credentials for the Administrator account.
3. Backdoor Investigation Procedure: 
   * Check Active Directory Creation Date & Attributes for backdoor.
   * Cross-reference against Honeypot configuration lists.
   * If unauthorized, disable the account immediately and audit AD Event Logs (4720 - User Created) to identify who created it.
4. Detection Improvement: Deploy a real-time Splunk alert triggering when EventCode 4771 exceeds 5 failures from a single IP within a 1-minute window.

---

## 💡 Lessons Learned
* Log Parsing Gaps: SIEM parsers must be updated to automatically map Kerberos fields without relying on manual SPL extraction during active triage.
* Proactive Alerting: Reliance on manual threat hunting allowed the attack to occur before detection; real-time threshold alerts are required for Kerberos anomalies.

---
*Investigated and documented by Ahmad Algassab | SOC Analyst & Security Engineer*
