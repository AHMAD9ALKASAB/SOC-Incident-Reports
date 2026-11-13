#!/usr/bin/env python3
"""
    Scenario 11 - Defense & Forensic Utilities
    Description: Python utility to parse Sysmon Process Creation (Event ID 1) logs and detect Office spawning Shells.
    Author: Ahmad Alqassab
"""

import sys

def analyze_sysmon_logs(log_file):
    print("=== Analyzing Sysmon Logs for VBA Stomping Patterns ===")
    
    # Simulated Sysmon Event ID 1 entries for demonstration
    # In live triage, this parses Windows Event Logs (XML/JSON) or Sysmon logs
    sample_logs = [
        {"EventID": 1, "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami"},
        {"EventID": 1, "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdA=="},
        {"EventID": 1, "ParentImage": "C:\\Windows\\explorer.exe", "Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "notepad.exe"}
    ]
    
    office_processes = ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE"]
    suspicious_shells = ["CMD.EXE", "POWERSHELL.EXE", "WSCRIPT.EXE", "CSCRIPT.EXE"]

    alerts = 0
    for log in sample_logs:
        if log["EventID"] == 1:
            parent = log["ParentImage"].upper()
            child = log["Image"].upper()
            
            # Check if parent is an Office app and child is a shell
            is_office = any(office in parent for office in office_processes)
            is_shell = any(shell in child for shell in suspicious_shells)
            
            if is_office and is_shell:
                alerts += 1
                print(f"\n[!] ALERT: Suspicious Process Lineage Detected!")
                print(f"    Parent: {log['ParentImage']}")
                print(f"    Child : {log['Image']}")
                print(f"    Cmd   : {log['CommandLine']}")
                
                if "-enc" in log["CommandLine"].lower() or "-w hidden" in log["CommandLine"].lower():
                    print(f"    [🚨] CRITICAL: Encoded/Hidden PowerShell detected! Strong indicator of VBA Stomping.")

    print(f"\n[+] Analysis Complete. Total Suspicious Events Found: {alerts}")

if name == "main":
    analyze_sysmon_logs(None)
