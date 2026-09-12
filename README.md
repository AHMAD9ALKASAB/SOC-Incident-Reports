# 🛡️ SOC Incident Report: Kerberos Password Spraying Detection

## 📌 Executive Summary
During a routine Threat Hunting session, multiple Kerberos authentication failure events (EventCode 4771) were detected. Further investigation confirmed an automated Password Spraying Attack originating from an internal host targeting critical domain accounts.

---

## 🔍 Investigation & Technical Analysis

* Threat Type: Credential Access / Password Spraying
* Target Protocol: Kerberos (Pre-Authentication)
* Event ID: 4771 (Kerberos pre-authentication failed)
* Attacker IP Address: 172.16.66.1
* Target Domain: THREEBEESCO.COM
* Targeted Accounts: Administrator, backdoor
* Timestamp: 2020-07-22 23:29:36

### 💡 Key Findings
1. Attack Pattern: Rapid sequential authentication failures across multiple accounts within the same second (23:29:36.000), utilizing sequential source ports (55967, 55968).
2. Field Extraction Challenge: Raw log fields were unstructured in the default parsing view. Custom Regex (rex) was crafted to parse and isolate Client Address and Account Name dynamically.

---

## 🛠️ Detection Query (Splunk SPL)

`spl
index=* EventCode=4771 
| rex "Account Name:\s+(?<user>\S+)" 
| rex "Client Address:\s+(?<ip>\S+)" 
| stats count by ip, user


---

## 🚨 Mitigation & Recommendations

1. Containment: Isolate host 172.16.66.1 immediately at the network/firewall level.
2. Account Hardening: Enforce Multi-Factor Authentication (MFA) and reset credentials for the Administrator account. Inspect the backdoor account to identify if it serves as a honeypot or unauthorized persistence.
3. Detection Improvement: Deploy a real-time Splunk alert triggering when EventCode 4771 exceeds 5 failures from a single IP within a 1-minute window.

---
*Investigated and documented by Ahmad Algassab | SOC Analyst & Security Engineer*
