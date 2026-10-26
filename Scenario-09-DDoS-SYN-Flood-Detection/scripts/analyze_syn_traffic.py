#!/usr/bin/env python3
"""
    Scenario 09 - Defense & Forensic Utilities
    Description: Python utility to parse network logs or PCAP metadata and detect high-rate SYN floods.
    Author: Ahmad Alqassab
"""

import sys
from collections import defaultdict

def analyze_syn_traffic(log_file):
    print("=== Analyzing Network Telemetry for SYN Flood Patterns ===")
    syn_counts = defaultdict(int)
    
    # Simulated packet entries for demonstration
    # In live triage, this parses firewall or NetFlow CSV/JSON logs
    sample_logs = [
        {"src_ip": "198.51.100.45", "flags": "SYN", "port": 443},
        {"src_ip": "198.51.100.89", "flags": "SYN", "port": 443},
        {"src_ip": "203.0.113.112", "flags": "SYN", "port": 443},
    ]
    
    for packet in sample_logs:
        if packet["flags"] == "SYN":
            syn_counts[packet["src_ip"]] += 1
            
    print(f"[+] Total Unique Source IPs analyzed: {len(syn_counts)}")
    for ip, count in syn_counts.items():
        print(f"    Source IP: {ip} | SYN Packets Flagged: {count}")
        if count > 1000:
            print(f"    [!] ALERT: High volume SYN packets detected from {ip}!")

if name == "main":
    analyze_syn_traffic(None)
