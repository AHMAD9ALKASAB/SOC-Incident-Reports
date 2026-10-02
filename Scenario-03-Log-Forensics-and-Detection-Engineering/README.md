# Scenario 03: Web Log Forensics & Behavioral Detection Engineering

## 📌 Executive Summary
This report documents a hands-on investigation into web server access logs using Linux Command Line Interface (CLI) tools, followed by the development of behavioral detection rules using Sigma and Splunk Search Processing Language (SPL). It also introduces a standardized AI Master Prompt framework designed to act as a SOC Copilot for crafting robust, evasion-resistant detection logic.

---

## 🔍 Phase 1: Interactive & Automated Log Parsing (Linux CLI)
To process raw log data efficiently without relying on heavy SIEM infrastructure, core Linux utilities (grep, awk, sort, uniq) were leveraged to isolate attack vectors and summarize server responses.

### Key Analysis Commands:
# 1. Identify Top Requesting / Attacking IP Addresses
awk '{print $1}' access.log | sort | uniq -c | sort -nr

# 2. Extract Suspected Exploitation Payloads (SQLi, LFI, Double Encoding)
grep -Ei 'UNION|select|%252f|\.\.' access.log

# 3. HTTP Status Code Breakdown (Success vs. Failure Rates)
awk '{print $9}' access.log | sort | uniq -c
---

## 🛡️ Phase 2: Analyzed Threat Vectors & Impact Assessment

| Threat Vector | Attack Technique | Key Indicator (IoC / Behavioral Pattern) | Impact & Status |
| :--- | :--- | :--- | :--- |
| SQL Injection | In-Band Union-Based Exfiltration | UNION SELECT 1,group_concat(...) | Confirmed Exfiltration (200 OK, 4521 bytes) |
| Command Injection | OS Command Chaining | ; cat /etc/passwd via python-requests/2.31.0 | Execution Attempt (200 OK & 500 Error) |
| Directory Traversal / LFI | Double URL Encoding Bypass | %252f%252f..%252fetc%252fpasswd | Confirmed Compromise (200 OK, 12KB payload) |
| Log4Shell (CVE-2021-44228) | Header Injection & Obfuscation | ${jndi:ldap://...} inside User-Agent | Detected & Mitigated |

---

## 🎯 Phase 3: Detection Engineering (Behavioral vs. Hardcoded)

Hardcoded IoC detection (e.g., matching a static string like file=../../../etc/passwd) creates severe security blind spots. Effective detection engineering focuses on behavioral patterns and evasion mechanisms (such as double encoding, variable protocols, and response codes).

### 1. Sigma Rule: Generic Log4Shell / JNDI Exploitation (YAML)
title: Log4Shell JNDI Injection Exploitation Attempt (Generic Behavioral Pattern)
id: 5ea8faa8-db8b-45be-89b0-151b84c82702
status: experimental
description: Detects exploitation attempts targeting Log4Shell (CVE-2021-44228) by identifying generic JNDI patterns and common obfuscation techniques across web logs.
author: Ahmad Alqassab
date: 2026-10-02
logsource:
    category: webserver
detection:
    selection_jndi_structure:
        - '${jndi:'
        - '${jndi:${'
        - 'jndi:ldap'
        - 'jndi:rmi'
        - 'jndi:dns'
        - 'jndi:iiop'
    selection_obfuscation:
        - '/$%7bjndi:'
        - '%24%7bjndi:'
        - '$%7Bjndi:'
        - '%2524%257Bjndi'
        - '${::-j}${'
        - '${${lower:j}ndi:'
        - '${${upper:j}ndi:'
    filter_scanners:
        - 'w.nessus.org/nessus'
    condition: (selection_jndi_structure or selection_obfuscation) and not filter_scanners
falsepositives:
    - Authorized vulnerability scanners (e.g., Nessus, Burp Collaborator).
level: high
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2021-44228
### 2. Splunk Search Processing Language (SPL) Query
| from datamodel Web.Web
| regex _raw="[jJnNdDiI]{4}(\:|\%3A|\/|\%2F)\w+(\:\/\/|\%3A\%2F\%2F)(\$\{.*?\}(\.)?)?"
| eval jndi_protocol=if(match(_raw,"(?i)jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http|https):"), "YES", "NO")
| where jndi_protocol="YES" AND (status=200 OR status=302)
| stats count as injection_attempts, min(_time) as first_seen, max(_time) as last_seen values(src) as source_ips, values(url) as target_paths, values(http_user_agent) as user_agents by dest, jndi_protocol
| convert ctime(first_seen) ctime(last_seen)
| sort - injection_attempts
---

## 🤖 Phase 4: AI Copilot Detection Engineering Framework (Master Prompt)

To standardize and accelerate detection engineering workflows without compromising quality or overfitting, the following master prompt is utilized for AI-assisted rule generation:

You are a Senior Detection Engineer operating under a behavioral-based detection methodology.

I will provide you with incident data, raw logs, or an attack payload. Your objective is to analyze the input and produce robust, generic, and evasion-resistant detection logic.

[ INPUT DATA ]
- Attack Vector: <Attack / CVE Name>
- Raw Payload / Path: <Insert Log Path Raw or>
- Log Source: <e.g., Apache Access Log / Windows Event / Web Firewall>

[ RULES & CONSTRAINTS ]
1. No Hardcoding: Avoid static matching on specific file names or domains. Extract generic behavioral patterns.
2. Evasion Resistance: Account for URL encoding, double encoding, obfuscation, and protocol variations.
3. False Positive Handling: Include response code filters (e.g., status=200) to prioritize actual impacts over blocked noise.

[ REQUIRED OUTPUT FORMAT ]
1. Generic Sigma Rule (YAML):
   - Metadata, MITRE ATT&CK mapping, generic selection logic, and false positives.
2. Optimized Splunk SPL Query:
   - Pattern extraction, status code filtering, stats aggregation, and readable aliases.
3. Blind Spot Analysis:
   - Identify potential bypass techniques and recommended future enhancements.
---

## 💡 Philosophy: "Code Intuition" (فراسة الكود)
Automated tools report what happened, but true security analysis begins when the defender understands human intent behind software decisions and malicious queries. Transforming raw logs into behavioral detection rules bridges the gap between passive monitoring and proactive threat defense.
