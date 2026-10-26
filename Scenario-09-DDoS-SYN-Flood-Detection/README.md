# Scenario 09: Distributed Denial of Service (DDoS) & TCP SYN Flood Forensics

## 📌 Executive Summary
This report investigates a high-rate Distributed Denial of Service (DDoS) attack targeting a primary web server (10.0.1.100). The adversary leveraged multiple disparate source IP addresses (198.51.100.45, 198.51.100.89, and 203.0.113.112) executing a synchronized TCP SYN Flood attack. The objective was to overwhelm the server's connection table by exhausting half-open socket allocations during the TCP three-way handshake, bypassing naive single-IP rate limits.

---

## 🔍 Phase 1: Packet Telemetry & Triage Analysis
Correlation of netflow and firewall telemetry captured during the incident window revealed the following attack pattern:

### Extracted Incident Telemetry:
| Timestamp (UTC) | Source IP | Destination IP | Dest Port | TCP Flags | Packet Rate (pkts/sec) | Analysis Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-10-24 14:10:02.102 | 198.51.100.45 | 10.0.1.100 | 443 | SYN (0x02) | 14,500 | Synchronized burst (Millisecond offset) |
| 2026-10-24 14:10:02.854 | 198.51.100.89 | 10.0.1.100 | 443 | SYN (0x02) | 16,200 | Parallel multi-source flooding |
| 2026-10-24 14:10:01.500 | 203.0.113.112 | 10.0.1.100 | 443 | SYN (0x02) | 15,100 | Paced lead-in burst |

> Key Observation: The attacker distributed the volumetric load across multiple IPs and tightly coordinated timestamps down to the millisecond scale. This prevented single-source IP reputation blocks and overwhelmed the target's half-open connection queue (backlog queue).

---

## 🧪 Phase 2: Protocol Deconstruction & Code Intuition
Analyzing volumetric network attacks requires evaluating the core mechanics of the TCP protocol:

* The Three-Way Handshake Vulnerability: Normally, a client sends SYN, the server responds with SYN-ACK, and the client completes with ACK. In a SYN flood, the server allocates memory for the half-open connection upon receiving SYN, but the final ACK is never sent by the attacker.
* Why Perimeter Defenses Fail: Traditional stateless firewalls inspect packets individually. Since a standalone SYN packet is syntactically valid, it does not trigger signature-based alerts. Only behavioral analysis and connection-state tracking can flag the anomaly.
* Distributed Evasion (DDoS): By splitting traffic across multiple source IPs with staggered millisecond offsets, the attack mimics high-concurrency legitimate traffic, evading simplistic threshold-based rate limiters.

---

## 🛡️ Phase 3: Incident Response & Mitigation (NIST Framework)

To immediately restore service availability and mitigate the flood:

### 1. Active Containment
* SYN Cookies Activation: Enabled kernel-level SYN cookies on the load balancer/server to stop allocating memory for half-open connections until the handshake completes.
* Rate Limiting & BGP Flowspec: Applied dynamic rate-limiting rules at the upstream edge firewall to drop traffic originating from the malicious source subnets.

### 2. Hardening Measures
* Adjusted TCP backlog queue limits and reduced SYN-ACK retry timeouts (TcpMaxConnectResponseRetransmissions).

---

## 🎯 Phase 4: Behavioral Detection Engineering

To proactively catch volumetric SYN floods and DDoS attempts:

### 1. Splunk SPL Query (Anomalous Half-Open Connection Volume)
index=firewall action=allowed dest_ip="10.0.1.100" tcp_flags="SYN"
| stats count as syn_packets, dc(src_ip) as unique_sources by dest_ip, span=1s
| where syn_packets > 10000 AND unique_sources > 1
| eval threat_indicator="Potential Distributed TCP SYN Flood Attack"
| table _time, dest_ip, syn_packets, unique_sources, threat_indicator
### 2. Sigma Rule Concept (YAML)
`yaml
title: Distributed TCP SYN Flood Attack Detection
id: d45e812b-77f9-4b1a-9f5b-111111110009
status: experimental
description: Detects high-volume volumetric SYN packets directed at a single destination from multiple distinct IP addresses within a short timeframe.
author: Ahmad Alqassab
references:
  - https://github.com/AHMAD9ALKASAB/SOC-Incident-Reports
logsource:
  product: firewall
  service: packet_filter
detection:
  selection:
    DestinationPort: [80, 443]
    TcpFlags: 'SYN'
  timeframe: 5s
  condition: selection | count(SourceIp) > 3 and count() > 20000
falsepositives:
  - Legitimate flash-crowd traffic or massive corporate proxy egress points
level: high
tags:
  - attack.impact
  - attack.t1498.001
---

## 💡 Philosophy: "Code Intuition" (فراسة الكود)
Denial of service is not just about raw bandwidth; it is about exploiting stateful resource allocation. Effective threat hunting requires looking beyond individual packet contents to analyze state metrics, connection ratios, and temporal distribution across network interfaces.
