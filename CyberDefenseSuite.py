#!/usr/bin/env python3
"""
=============================================================================
CyberDefense Suite - Unified Security Analysis Toolkit
CYBR3220 Final Project - Dalair
=============================================================================
This tool consolidates multiple defensive cybersecurity capabilities:
- File pattern scanning (YARA/regex)
- Folder security analysis
- Network traffic analysis (PCAP)
- File integrity monitoring
- Process analysis
- Port connection monitoring
- System log analysis
- USB device tracking
=============================================================================
"""

import os
import sys
import re
import yara
import hashlib
import subprocess
import platform
from datetime import datetime
from collections import Counter

# ANSI color codes for terminal output
RESET = "\033[0m"
CYAN = "\033[38;5;39m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"


# =============================================================================
# BANNER & MENU SYSTEM
# =============================================================================

def banner():
    """Display tool banner"""
    print(CYAN + """
   ______      __             ____       ____                     
  / ____/_  __/ /_  ___  ____/ __ \___  / __/__  ____  _________ 
 / /   / / / / __ \/ _ \/ __  / / / _ \/ /_/ _ \/ __ \/ ___/ _ \\
/ /___/ /_/ / /_/ /  __/ /_/ / /_/  __/ __/  __/ / / (__  )  __/
\____/\__, /_.___/\___/\__,_/_____/\___/_/  \___/_/ /_/____/\___/ 
     /____/                                                        
    """ + RESET)
    print(GREEN + "           Unified Security Analysis Toolkit" + RESET)
    print(GREEN + "           CYBR3220 Final Project - Dalair" + RESET)
    print()


def main_menu():
    """Display main menu and get user choice"""
    print("=" * 70)
    print("MAIN MENU - Select a Security Analysis Module")
    print("=" * 70)
    print()
    print("[1]  File Pattern Scanner (YARA/Regex)")
    print("[2]  Folder Security Scanner (Phishing Detection)")
    print("[3]  PCAP Network Traffic Analyzer")
    print("[4]  File Integrity Monitor (Hash Comparison)")
    print("[5]  Process Monitor (Suspicious Process Detection)")
    print("[6]  Port Connection Analyzer (Active Connections)")
    print("[7]  System Log Analyzer (Security Events)")
    print("[8]  USB Device Monitor (Device Connection Log)")
    print()
    print("[0]  Exit")
    print()
    print("=" * 70)
    choice = input("Enter your choice: ").strip()
    return choice


# =============================================================================
# MODULE 1: FILE PATTERN SCANNER (YARA/REGEX)
# =============================================================================

def file_pattern_scanner():
    """
    Scan files for malicious patterns using YARA rules and regex
    Detects: reverse shells, credential dumping, download behavior, 
             packed executables, registry persistence, suspicious keywords
    """
    print("\n" + "=" * 70)
    print("MODULE 1: FILE PATTERN SCANNER")
    print("=" * 70)
    
    file_path = input("\nEnter file path to scan: ").strip().strip('"')
    
    if not os.path.exists(file_path):
        print(f"{RED}[ERROR] File not found: {file_path}{RESET}")
        return
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"{RED}[ERROR] Could not read file: {e}{RESET}")
        return
    
    print(f"\n{GREEN}[+] Scanning: {file_path}{RESET}")
    print("-" * 70)
    
    findings = []
    
    # Pattern 1: Reverse Shell Indicators
    print("\n[*] Checking for reverse shell indicators...")
    reverse_shell_pattern = r"(cmd\.exe|socket|connect|subprocess\.Popen|/bin/bash|/bin/sh)"
    reverse_shell_matches = re.findall(reverse_shell_pattern, content, re.IGNORECASE)
    if reverse_shell_matches:
        findings.append(f"{RED}[!] REVERSE SHELL INDICATORS: {set(reverse_shell_matches)}{RESET}")
    
    reverse_shell_rule = """
    rule Reverse_Shell
    {
        strings:
            $a = "cmd.exe"
            $b = "socket"
            $c = "connect"
            $d = "subprocess.Popen"
        condition:
            any of them
    }
    """
    if yara.compile(source=reverse_shell_rule).match(data=content):
        findings.append(f"{RED}[!] YARA: Reverse shell pattern detected{RESET}")
    
    # Pattern 2: Credential Dumping
    print("[*] Checking for credential dumping tools...")
    cred_pattern = r"(lsass|mimikatz|ntds|password|dump|hashdump)"
    cred_matches = re.findall(cred_pattern, content, re.IGNORECASE)
    if cred_matches:
        findings.append(f"{RED}[!] CREDENTIAL DUMPING: {set(cred_matches)}{RESET}")
    
    # Pattern 3: Download Behavior
    print("[*] Checking for download/exfiltration behavior...")
    download_pattern = r"(wget|curl|Invoke-WebRequest|DownloadFile|urllib\.request)"
    download_matches = re.findall(download_pattern, content, re.IGNORECASE)
    if download_matches:
        findings.append(f"{YELLOW}[!] DOWNLOAD BEHAVIOR: {set(download_matches)}{RESET}")
    
    # Pattern 4: Registry Persistence
    print("[*] Checking for registry persistence mechanisms...")
    registry_pattern = r"(HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|Run|RunOnce|winreg)"
    registry_matches = re.findall(registry_pattern, content, re.IGNORECASE)
    if registry_matches:
        findings.append(f"{YELLOW}[!] REGISTRY PERSISTENCE: {set(registry_matches)}{RESET}")
    
    # Pattern 5: Suspicious Keywords
    print("[*] Checking for general malware keywords...")
    malware_pattern = r"(keylogger|trojan|backdoor|rootkit|ransomware|exploit)"
    malware_matches = re.findall(malware_pattern, content, re.IGNORECASE)
    if malware_matches:
        findings.append(f"{RED}[!] MALWARE KEYWORDS: {set(malware_matches)}{RESET}")
    
    # Pattern 6: IP Addresses
    print("[*] Extracting IP addresses...")
    ip_pattern = r"\b\d{1,3}(\.\d{1,3}){3}\b"
    ip_matches = re.findall(ip_pattern, content)
    if ip_matches:
        # Reconstruct full IPs
        full_ips = [match[0] if isinstance(match, tuple) else match for match in ip_matches]
        findings.append(f"{BLUE}[*] IP ADDRESSES FOUND: {set(full_ips)}{RESET}")
    
    # Pattern 7: Email Addresses
    print("[*] Extracting email addresses...")
    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    email_matches = re.findall(email_pattern, content)
    if email_matches:
        findings.append(f"{BLUE}[*] EMAIL ADDRESSES: {set(email_matches)}{RESET}")
    
    # Display results
    print("\n" + "=" * 70)
    print("SCAN RESULTS")
    print("=" * 70)
    
    if findings:
        for finding in findings:
            print(finding)
    else:
        print(f"{GREEN}[+] No suspicious patterns detected{RESET}")
    
    print("\n" + "=" * 70)
    input("\nPress Enter to return to main menu...")


# =============================================================================
# MODULE 2: FOLDER SECURITY SCANNER
# =============================================================================

def folder_security_scanner():
    """
    Scan folder for files containing phishing/suspicious keywords
    Based on the GUI Folder Security Scanner from class
    """
    print("\n" + "=" * 70)
    print("MODULE 2: FOLDER SECURITY SCANNER")
    print("=" * 70)
    
    folder_path = input("\nEnter folder path to scan: ").strip().strip('"')
    
    if not os.path.exists(folder_path):
        print(f"{RED}[ERROR] Folder not found: {folder_path}{RESET}")
        return
    
    if not os.path.isdir(folder_path):
        print(f"{RED}[ERROR] Path is not a directory: {folder_path}{RESET}")
        return
    
    # Suspicious keywords list (from class GUI scanner)
    suspicious_words = [
        # Urgency / Pressure
        "urgent", "immediately", "asap", "action required", "important", "alert",
        # Account / Security
        "account", "account suspended", "account locked", "verify", "verification",
        "confirm", "security alert", "unauthorized", "suspicious activity",
        # Credentials
        "password", "username", "login", "signin", "credentials", "reset password",
        # Financial / Banking
        "bank", "credit card", "debit card", "payment", "transaction",
        "billing", "invoice", "refund", "transfer", "wire", "deposit",
        # Threat / Fear
        "suspended", "terminated", "blocked", "restricted", "penalty",
        "legal action", "fine", "court", "lawsuit",
        # Links / Actions
        "click here", "click below", "open link", "download", "attachment",
        "update", "upgrade", "install", "access now",
        # Personal Info Requests
        "ssn", "social security", "date of birth", "dob", "pin",
        "otp", "verification code", "security code",
        # Prize / Scam
        "winner", "won", "prize", "lottery", "free", "gift", "claim now", "limited offer",
        # Email Tricks
        "dear user", "dear customer", "official notice", "final warning",
        # Tech / IT Scams
        "virus detected", "malware", "system infected", "technical support",
        "remote access", "support team"
    ]
    
    print(f"\n{GREEN}[+] Scanning folder: {folder_path}{RESET}")
    print("-" * 70)
    
    results = []
    
    for filename in os.listdir(folder_path):
        if filename.endswith(".txt"):
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path, "r", encoding="utf-8", errors='ignore') as file:
                    content = file.read().lower()
                    found = [word for word in suspicious_words if word in content]
                    
                    if found:
                        results.append((filename, found, "WARNING"))
                    else:
                        results.append((filename, [], "SAFE"))
            except Exception as e:
                results.append((filename, [str(e)], "ERROR"))
    
    # Display results
    print("\n" + "=" * 70)
    print("SCAN RESULTS")
    print("=" * 70)
    
    if not results:
        print(f"{YELLOW}[!] No .txt files found in folder{RESET}")
    else:
        for filename, keywords, status in results:
            if status == "WARNING":
                print(f"\n{RED}[WARNING] {filename}{RESET}")
                print(f"  Keywords: {', '.join(keywords[:10])}")  # Limit to first 10
            elif status == "SAFE":
                print(f"\n{GREEN}[SAFE] {filename}{RESET}")
            elif status == "ERROR":
                print(f"\n{RED}[ERROR] {filename}: {keywords[0]}{RESET}")
    
    print("\n" + "=" * 70)
    input("\nPress Enter to return to main menu...")


# =============================================================================
# MODULE 3: PCAP NETWORK TRAFFIC ANALYZER
# =============================================================================

def pcap_analyzer():
    """
    Analyze network traffic from PCAP files
    Based on pcap_analyzer_advanced.py from class
    """
    print("\n" + "=" * 70)
    print("MODULE 3: PCAP NETWORK TRAFFIC ANALYZER")
    print("=" * 70)
    
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    except ImportError:
        print(f"{RED}[ERROR] scapy module not installed{RESET}")
        print(f"{YELLOW}Install with: pip install scapy{RESET}")
        input("\nPress Enter to return to main menu...")
        return
    
    pcap_path = input("\nEnter PCAP file path: ").strip().strip('"')
    
    if not os.path.exists(pcap_path):
        print(f"{RED}[ERROR] File not found: {pcap_path}{RESET}")
        input("\nPress Enter to return to main menu...")
        return
    
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"{RED}[ERROR] Could not read PCAP: {e}{RESET}")
        input("\nPress Enter to return to main menu...")
        return
    
    if len(packets) == 0:
        print(f"{YELLOW}[!] PCAP file contains no packets{RESET}")
        input("\nPress Enter to return to main menu...")
        return
    
    # Analysis counters
    protocol_counter = Counter()
    source_ip_counter = Counter()
    destination_ip_counter = Counter()
    tcp_port_counter = Counter()
    udp_port_counter = Counter()
    packet_sizes = []
    
    # Process packets
    for packet in packets:
        packet_sizes.append(len(packet))
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            source_ip_counter[src_ip] += 1
            destination_ip_counter[dst_ip] += 1
            
            if TCP in packet:
                protocol_counter["TCP"] += 1
                tcp_port_counter[packet[TCP].dport] += 1
            elif UDP in packet:
                protocol_counter["UDP"] += 1
                udp_port_counter[packet[UDP].dport] += 1
            elif ICMP in packet:
                protocol_counter["ICMP"] += 1
            else:
                protocol_counter["Other IP"] += 1
        else:
            protocol_counter["Non-IP"] += 1
    
    # Calculate statistics
    total_packets = len(packets)
    avg_packet_size = sum(packet_sizes) / len(packet_sizes)
    
    # Display results
    print("\n" + "=" * 70)
    print("NETWORK TRAFFIC ANALYSIS RESULTS")
    print("=" * 70)
    
    print(f"\n{GREEN}Capture File: {os.path.basename(pcap_path)}{RESET}")
    print(f"Total Packets: {total_packets}")
    print(f"Average Packet Size: {avg_packet_size:.2f} bytes")
    
    # Protocol breakdown
    print("\n" + "-" * 70)
    print("PROTOCOL BREAKDOWN")
    print("-" * 70)
    for proto in ["TCP", "UDP", "ICMP", "Other IP", "Non-IP"]:
        count = protocol_counter.get(proto, 0)
        percentage = (count / total_packets * 100) if total_packets > 0 else 0
        print(f"{proto:<15} {count:>6} packets ({percentage:>5.2f}%)")
    
    # Top source IPs
    print("\n" + "-" * 70)
    print("TOP 5 SOURCE IP ADDRESSES")
    print("-" * 70)
    for ip, count in source_ip_counter.most_common(5):
        print(f"{ip:<20} {count:>6} packets")
    
    # Top destination IPs
    print("\n" + "-" * 70)
    print("TOP 5 DESTINATION IP ADDRESSES")
    print("-" * 70)
    for ip, count in destination_ip_counter.most_common(5):
        print(f"{ip:<20} {count:>6} packets")
    
    # TCP ports
    if tcp_port_counter:
        print("\n" + "-" * 70)
        print("TOP TCP PORTS")
        print("-" * 70)
        for port, count in tcp_port_counter.most_common(5):
            print(f"Port {port:<10} {count:>6} packets")
    
    # UDP ports
    if udp_port_counter:
        print("\n" + "-" * 70)
        print("TOP UDP PORTS")
        print("-" * 70)
        for port, count in udp_port_counter.most_common(5):
            print(f"Port {port:<10} {count:>6} packets")
    
    print("\n" + "=" * 70)
    input("\nPress Enter to return to main menu...")


# =============================================================================
# MODULE 4: FILE INTEGRITY MONITOR
# =============================================================================

def file_integrity_monitor():
    """
    Calculate and compare file hashes to detect tampering
    Uses SHA256 hashing
    """
    print("\n" + "=" * 70)
    print("MODULE 4: FILE INTEGRITY MONITOR")
    print("=" * 70)
    
    print("\nSelect operation:")
    print("[1] Generate baseline hash")
    print("[2] Verify file against baseline")
    
    choice = input("\nEnter choice: ").strip()
    
    if choice == "1":
        # Generate baseline
        file_path = input("\nEnter file path: ").strip().strip('"')
        
        if not os.path.exists(file_path):
            print(f"{RED}[ERROR] File not found{RESET}")
            input("\nPress Enter to return to main menu...")
            return
        
        try:
            file_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    file_hash.update(chunk)
            
            hash_value = file_hash.hexdigest()
            
            print(f"\n{GREEN}[+] SHA256 Hash: {hash_value}{RESET}")
            
            # Save to baseline file
            baseline_file = file_path + ".baseline"
            with open(baseline_file, 'w') as f:
                f.write(hash_value)
            
            print(f"{GREEN}[+] Baseline saved to: {baseline_file}{RESET}")
        
        except Exception as e:
            print(f"{RED}[ERROR] {e}{RESET}")
    
    elif choice == "2":
        # Verify against baseline
        file_path = input("\nEnter file path: ").strip().strip('"')
        baseline_file = file_path + ".baseline"
        
        if not os.path.exists(file_path):
            print(f"{RED}[ERROR] File not found{RESET}")
            input("\nPress Enter to return to main menu...")
            return
        
        if not os.path.exists(baseline_file):
            print(f"{RED}[ERROR] Baseline file not found: {baseline_file}{RESET}")
            input("\nPress Enter to return to main menu...")
            return
        
        try:
            # Calculate current hash
            file_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    file_hash.update(chunk)
            
            current_hash = file_hash.hexdigest()
            
            # Read baseline
            with open(baseline_file, 'r') as f:
                baseline_hash = f.read().strip()
            
            print(f"\nBaseline Hash: {baseline_hash}")
            print(f"Current Hash:  {current_hash}")
            
            if current_hash == baseline_hash:
                print(f"\n{GREEN}[+] INTEGRITY CHECK PASSED - File has not been modified{RESET}")
            else:
                print(f"\n{RED}[!] INTEGRITY CHECK FAILED - File has been tampered with!{RESET}")
        
        except Exception as e:
            print(f"{RED}[ERROR] {e}{RESET}")
    
    else:
        print(f"{RED}[ERROR] Invalid choice{RESET}")
    
    print("\n" + "=" * 70)
    input("\nPress Enter to return to main menu...")


# =============================================================================
# MODULE 5: PROCESS MONITOR
# =============================================================================

def process_monitor():
    """
    List running processes and flag suspicious ones
    Works on Windows and Linux
    """
    print("\n" + "=" * 70)
    print("MODULE 5: PROCESS MONITOR")
    print("=" * 70)
    
    suspicious_names = [
        'mimikatz', 'procdump', 'pwdump', 'hashdump', 'keylogger',
        'backdoor', 'netcat', 'nc.exe', 'psexec', 'remote',
        'vnc', 'teamviewer', 'anydesk'
    ]
    
    print(f"\n{GREEN}[+] Scanning running processes...{RESET}")
    print("-" * 70)
    
    try:
        if platform.system() == "Windows":
            # Windows: use tasklist
            result = subprocess.run(['tasklist'], capture_output=True, text=True)
            output = result.stdout
        else:
            # Linux: use ps
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            output = result.stdout
        
        lines = output.split('\n')
        suspicious_found = []
        
        for line in lines:
            for suspicious in suspicious_names:
                if suspicious.lower() in line.lower():
                    suspicious_found.append(line)
                    break
        
        if suspicious_found:
            print(f"\n{RED}[!] SUSPICIOUS PROCESSES DETECTED:{RESET}\n")
            for proc in suspicious_found:
                print(f"{RED}{proc}{RESET}")
        else:
            print(f"\n{GREEN}[+] No obviously suspicious processes detected{RESET}")
        
        print(f"\n{BLUE}[*] Total processes listed: {len(lines)}{RESET}")
    
    except Exception as e:
        print(f"{RED}[ERROR] {e}{RESET}")
    
    print("\n" + "=" * 70)
    input("\nPress Enter to return to main menu...")


# =============================================================================
# MODULE 6: PORT CONNECTION ANALYZER
# =============================================================================

def port_connection_analyzer():
    """
    Analyze active network connections using netstat
    Flag unusual ports and connections
    """
    print("\n" + "=" * 70)
    print("MODULE 6: PORT CONNECTION ANALYZER")
    print("=" * 70)
    
    suspicious_ports = [23, 3389, 4444, 5555, 6666, 8080, 31337]
    
    print(f"\n{GREEN}[+] Analyzing active network connections...{RESET}")
    print("-" * 70)
    
    try:
        if platform.system() == "Windows":
            result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
        else:
            result = subprocess.run(['netstat', '-tunap'], capture_output=True, text=True)
        
        output = result.stdout
        lines = output.split('\n')
        
        suspicious_connections = []
        listening_ports = []
        
        for line in lines:
            if 'LISTEN' in line or 'ESTABLISHED' in line:
                for port in suspicious_ports:
                    if f":{port}" in line:
                        suspicious_connections.append(line)
                        break
                
                if 'LISTEN' in line:
                    listening_ports.append(line)
        
        # Display results
        if suspicious_connections:
            print(f"\n{RED}[!] SUSPICIOUS CONNECTIONS DETECTED:{RESET}\n")
            for conn in suspicious_connections[:10]:  # Limit to 10
                print(f"{RED}{conn}{RESET}")
        
        print(f"\n{BLUE}[*] Listening ports (first 10):{RESET}")
        for port_line in listening_ports[:10]:
            print(f"{BLUE}{port_line}{RESET}")
        
        print(f"\n{GREEN}[+] Total active connections: {len(lines)}{RESET}")
    
    except Exception as e:
        print(f"{RED}[ERROR] {e}{RESET}")
    
    print("\n" + "=" * 70)
    input("\nPress Enter to return to main menu...")


# =============================================================================
# MODULE 7: SYSTEM LOG ANALYZER
# =============================================================================

def system_log_analyzer():
    """
    Parse system logs for security events
    Focuses on failed logins and privilege escalations
    """
    print("\n" + "=" * 70)
    print("MODULE 7: SYSTEM LOG ANALYZER")
    print("=" * 70)
    
    print("\n[!] This module searches for security events in system logs")
    
    if platform.system() == "Windows":
        print(f"\n{YELLOW}[*] Windows Event Log analysis requires administrator privileges{RESET}")
        print(f"{YELLOW}[*] Searching for common log files...{RESET}")
        
        # Check common Windows log locations
        log_paths = [
            r"C:\Windows\System32\winevt\Logs\Security.evtx",
            r"C:\Windows\System32\winevt\Logs\System.evtx"
        ]
        
        found = False
        for log_path in log_paths:
            if os.path.exists(log_path):
                print(f"{GREEN}[+] Found: {log_path}{RESET}")
                found = True
        
        if not found:
            print(f"{RED}[!] No Windows event logs found or insufficient permissions{RESET}")
    
    else:
        # Linux log analysis
        log_paths = [
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/syslog"
        ]
        
        for log_path in log_paths:
            if os.path.exists(log_path):
                print(f"\n{GREEN}[+] Analyzing: {log_path}{RESET}")
                try:
                    with open(log_path, 'r', errors='ignore') as f:
                        lines = f.readlines()
                        
                        failed_logins = [line for line in lines if 'failed' in line.lower() and 'login' in line.lower()]
                        sudo_events = [line for line in lines if 'sudo' in line.lower()]
                        
                        if failed_logins:
                            print(f"\n{RED}[!] Failed login attempts (last 5):{RESET}")
                            for line in failed_logins[-5:]:
                                print(f"{RED}{line.strip()}{RESET}")
                        
                        if sudo_events:
                            print(f"\n{YELLOW}[*] Privilege escalation events (last 5):{RESET}")
                            for line in sudo_events[-5:]:
                                print(f"{YELLOW}{line.strip()}{RESET}")
                
                except PermissionError:
                    print(f"{RED}[!] Permission denied - run as root/administrator{RESET}")
                except Exception as e:
                    print(f"{RED}[ERROR] {e}{RESET}")
    
    print("\n" + "=" * 70)
    input("\nPress Enter to return to main menu...")


# =============================================================================
# MODULE 8: USB DEVICE MONITOR
# =============================================================================

def usb_device_monitor():
    """
    Monitor and log USB device connections
    Platform-specific implementation
    """
    print("\n" + "=" * 70)
    print("MODULE 8: USB DEVICE MONITOR")
    print("=" * 70)
    
    print(f"\n{GREEN}[+] Checking for USB device history...{RESET}")
    print("-" * 70)
    
    if platform.system() == "Windows":
        print(f"\n{YELLOW}[*] Windows USB device history (Registry-based){RESET}")
        print(f"{YELLOW}[*] This feature requires Windows and registry access{RESET}")
        
        # On Windows, USB info is in registry
        # HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR
        try:
            result = subprocess.run(
                ['reg', 'query', r'HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print(f"\n{GREEN}[+] USB device registry entries found:{RESET}\n")
                print(result.stdout[:1000])  # Limit output
            else:
                print(f"{RED}[!] Could not access USB device registry{RESET}")
        
        except Exception as e:
            print(f"{RED}[ERROR] {e}{RESET}")
    
    else:
        # Linux: check dmesg and /var/log/messages
        print(f"\n{YELLOW}[*] Linux USB device log (dmesg){RESET}")
        
        try:
            result = subprocess.run(['dmesg'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            usb_lines = [line for line in lines if 'usb' in line.lower()]
            
            if usb_lines:
                print(f"\n{GREEN}[+] USB-related events (last 10):{RESET}\n")
                for line in usb_lines[-10:]:
                    print(line)
            else:
                print(f"{YELLOW}[!] No USB events found in dmesg{RESET}")
        
        except Exception as e:
            print(f"{RED}[ERROR] {e}{RESET}")
    
    print("\n" + "=" * 70)
    input("\nPress Enter to return to main menu...")


# =============================================================================
# MAIN PROGRAM LOOP
# =============================================================================

def main():
    """Main program loop"""
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        banner()
        choice = main_menu()
        
        if choice == "1":
            file_pattern_scanner()
        elif choice == "2":
            folder_security_scanner()
        elif choice == "3":
            pcap_analyzer()
        elif choice == "4":
            file_integrity_monitor()
        elif choice == "5":
            process_monitor()
        elif choice == "6":
            port_connection_analyzer()
        elif choice == "7":
            system_log_analyzer()
        elif choice == "8":
            usb_device_monitor()
        elif choice == "0":
            print(f"\n{GREEN}[+] Exiting CyberDefense Suite{RESET}")
            print("=" * 70)
            sys.exit(0)
        else:
            print(f"\n{RED}[ERROR] Invalid choice{RESET}")
            input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()
