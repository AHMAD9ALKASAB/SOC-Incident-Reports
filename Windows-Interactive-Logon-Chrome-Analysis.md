# 🛡️ SOC Incident Report: Local Interactive Logon Anomaly via Browser Process

## 📌 Executive Summary
During a routine Windows Security Log analysis in Splunk, an unusual authentication pattern was detected. An interactive logon attempt (LogonType 2) was initiated directly by Google Chrome (chrome.exe). The initial attempt failed due to invalid credentials, followed closely by successful elevated authentication for the local account IEUser.

* Alert Source: SIEM Log Analysis / Windows Security Event Logs
* Severity Level: 🟡 MEDIUM (Potential Privilege Escalation / Browser Credential Abuse)
* Incident Status: Closed / Investigated

---

## 🔍 Investigation & Technical Analysis

* Threat Type: Credential Access / Local Interactive Authentication Anomaly
* Target Host: MSEDGEWIN10
* Target Account: IEUser
* Targeted Event Codes: 4624 (Logon Success), 4625 (Logon Failure)
* Logon Type: 2 (Interactive - Local Keyboard/Process Logon)
* Originating Process: C:\Program Files (x86)\Google\Chrome\Application\chrome.exe (PID: 0x1358)
* Logon Process Name: Chrome
* Impact Assessment: Initial authentication failure occurred, followed by successful authentication with elevated token rights (Elevated Token: Yes). No secondary lateral movement was identified.

### 📅 Attack Timeline
| Timestamp (UTC) | Event ID | Action | User | LogonType | Logon Process | Process Path |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2020-09-09 16:18:23 | 4625 | Failure | IEUser | 2 | Chrome | ...\Google\Chrome\Application\chrome.exe |
| 2020-09-09 16:18:25 | 4624 | Success | SYSTEM | 5 | Advapi | C:\Windows\System32\services.exe |
| 2020-09-09 16:18:27 | 4624 | Success | IEUser | 2 | Chrome | ...\Google\Chrome\Application\chrome.exe (Elevated Token) |
| 2020-09-09 16:18:27 | 4624 | Success | IEUser | 2 | Chrome | ...\Google\Chrome\Application\chrome.exe (Standard Token) |

### 💡 Key Technical Findings
1. Anomalous Authentication Source: Standard Windows Interactive Logons (LogonType 2) are typically mediated by winlogon.exe or lsass.exe. Direct invocation of interactive logons by browser applications (chrome.exe) indicates non-standard behavior such as local password managers, web-based administrative interfaces, or potential credential dumping/injection.
2. Initial Credential Rejection: Event 4625 confirmed a bad password attempt (Status: 0xC000006D, Sub Status: 0xC000006A), proving initial user error or automated credential testing before successful entry.
3. Privilege Elevation Context: The successful logon generated a split token pair (Elevated: Yes / Linked ID: 0x1CD964), granting administrative privileges to the session.

---

## 🛠️ Detection Query (Splunk SPL)

`spl
index=* (EventCode=4624 OR EventCode=4625)
| rex "Account Name:\s+(?<target_user>[^\r\n]+)"
| rex "Logon Type:\s+(?<logon_type>\d+)"
| rex "Process Name:\s+(?<process_path>[^\r\n]+)"
| rex "Logon Process:\s+(?<logon_proc>[^\r\n]+)"
| eval Action=if(EventCode==4624, "Success", "Failure")
| table _time, EventCode, Action, target_user, logon_type, logon_proc, process_path


🚨 Mitigation & Actionable Recommendations
​Endpoint Process Audit: Inspect browser extensions and background processes running within the IEUser profile on host MSEDGEWIN10.
​Credential Hygiene: Ensure local administrator credentials are unique and managed via LAPS (Local Administrator Password Solution) to mitigate local compromise impact.
​Detection Rule Enhancement: Create a SIEM detection alert for EventCode 4624/4625 where LogonType = 2 and ProcessName does NOT match standard system binaries (winlogon.exe, services.exe, lsass.exe).
​💡 Lessons Learned
​Process-Logon Correlation: Monitoring EventCode 4624 alone is insufficient; correlating the initiating ProcessName and Logon Process is critical to identifying non-standard authentication sources.
​Custom Field Parsing: Relying on default SIEM parsers can obscure critical audit details like Logon Process and Caller Process Name, making custom regex extraction essential during incident triage.
​Investigated and documented by Ahmad Algassab | SOC Analyst & Security Engineer
