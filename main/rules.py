from scapy.all import *
import re

# Define rules_list yang dibutuhkan analyst.py
rules_list = [
    {
        'name': 'TCP_SYN_Flood',
        'severity': 'high',
        'description': 'Possible TCP SYN Flood Attack detected',
        'conditions': {
            'protocol': 'TCP',
            'flags': 2  # SYN flag
        }
    },
    {
        'name': 'ICMP_Flood',
        'severity': 'medium',
        'description': 'Possible ICMP Flood Attack detected',
        'conditions': {
            'protocol': 'ICMP'
        }
    },
    {
        'name': 'Port_Scan',
        'severity': 'medium',
        'description': 'Possible Port Scan detected',
        'conditions': {
            'dst_port': [20, 21, 22, 23, 25, 53, 80, 443, 445]
        }
    },
    {
        'name': 'HTTP_Flood',
        'severity': 'medium',
        'description': 'Possible HTTP Flood Attack detected',
        'conditions': {
            'protocol': 'TCP',
            'dst_port': 80
        }
    }
]

def analyze_packet(packet):
    alerts = []
    
    # Check for TCP SYN Flood Attack
    if TCP in packet and packet[TCP].flags == 2:  # SYN flag
        alerts.append("Possible TCP SYN Flood Attack detected")
    
    # Check for ICMP Flood Attack
    if ICMP in packet:
        alerts.append("Possible ICMP Flood Attack detected")
        
    # Check for Port Scanning
    if TCP in packet and packet[TCP].dport in [20, 21, 22, 23, 25, 53, 80, 443, 445]:
        alerts.append(f"Possible Port Scan detected on port {packet[TCP].dport}")
        
    # Check for DNS Amplification Attack
    if DNS in packet and packet.qr == 0 and packet.opcode == 0:
        alerts.append("Possible DNS Amplification Attack detected")
        
    # Check for HTTP Flood Attack
    if TCP in packet and packet[TCP].dport == 80:
        if Raw in packet:
            payload = str(packet[Raw].load)
            if "HTTP" in payload:
                alerts.append("Possible HTTP Flood Attack detected")
                
    # Check for SQL Injection Attempt
    if Raw in packet:
        payload = str(packet[Raw].load).lower()
        sql_patterns = [
            'union select',
            'or 1=1',
            'drop table',
            'exec(',
            'xp_cmdshell'
        ]
        if any(pattern in payload for pattern in sql_patterns):
            alerts.append("Possible SQL Injection Attack detected")
            
    # Check for XSS Attack Attempt
    if Raw in packet:
        payload = str(packet[Raw].load).lower()
        xss_patterns = [
            '<script>',
            'javascript:',
            'onerror=',
            'onload=',
            'eval('
        ]
        if any(pattern in payload for pattern in xss_patterns):
            alerts.append("Possible XSS Attack detected")
    
    return alerts

def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    all_alerts = []
    
    for packet in packets:
        alerts = analyze_packet(packet)
        if alerts:
            all_alerts.extend(alerts)
    
    return all_alerts
