import pandas as pd
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import numpy as np
from scapy.all import rdpcap
import os
import sys

# Import rules_list from rules.py in the same directory
try:
    from .rules import rules_list
except ImportError:
    # Fallback for direct execution
    from rules import rules_list

def pcap_to_dataframe(pcap_file):
    """Convert PCAP file to DataFrame"""
    try:
        print(f"Reading PCAP file: {pcap_file}")
        packets = rdpcap(pcap_file)
        data = []
        
        for i, packet in enumerate(packets):
            try:
                row = {
                    'packet_id': i,
                    'timestamp': float(packet.time),
                    'protocol': 'Unknown',
                    'src_ip': 'Unknown',
                    'dst_ip': 'Unknown',
                    'src_port': 0,
                    'dst_port': 0,
                    'packet_length': len(packet),
                    'flags': 0  
                }
                
                # Extract IP layer information
                if packet.haslayer('IP'):
                    ip_layer = packet['IP']
                    row['src_ip'] = ip_layer.src
                    row['dst_ip'] = ip_layer.dst
                    row['protocol'] = ip_layer.proto
                
                # Extract TCP layer information
                if packet.haslayer('TCP'):
                    tcp_layer = packet['TCP']
                    row['src_port'] = tcp_layer.sport
                    row['dst_port'] = tcp_layer.dport
                    row['flags'] = tcp_layer.flags
                    row['protocol'] = 'TCP'
                
                # Extract UDP layer information
                elif packet.haslayer('UDP'):
                    udp_layer = packet['UDP']
                    row['src_port'] = udp_layer.sport
                    row['dst_port'] = udp_layer.dport
                    row['protocol'] = 'UDP'
                
                # Extract ICMP layer information
                elif packet.haslayer('ICMP'):
                    row['protocol'] = 'ICMP'
                
                data.append(row)
                
            except Exception as e:
                print(f"Error processing packet {i}: {str(e)}")
                continue
        
        df = pd.DataFrame(data)
        print(f"Successfully converted {len(df)} packets to DataFrame")
        return df
        
    except Exception as e:
        raise Exception(f"Error converting PCAP to DataFrame: {str(e)}")

def analyze_pcap(file_path):
    """Analyze PCAP file for network attacks"""
    try:
        print(f"Starting analysis of: {file_path}")
        
        # Check if file exists
        if not os.path.exists(file_path):
            raise Exception(f"File not found: {file_path}")
        
        # Convert PCAP to DataFrame
        df = pcap_to_dataframe(file_path)
        
        if df.empty:
            return {
                'error': 'No packets found in PCAP file',
                'status': 'failed'
            }
        
        # Initialize results dictionary
        analysis_results = {
            'alerts': [],
            'summary': {
                'total_packets': len(df),
                'total_alerts': 0,
                'attack_types': {},
                'ml_predictions': {},
                'protocols': df['protocol'].value_counts().to_dict(),
                'unique_ips': {
                    'source': df['src_ip'].nunique(),
                    'destination': df['dst_ip'].nunique()
                }
            },
            'status': 'success'
        }
        
        print(f"Applying rule-based detection on {len(df)} packets")
        
        # Apply rule-based detection
        for rule in rules_list:
            rule_name = rule['name']
            conditions = rule['conditions']
            
            # Create a mask based on rule conditions
            mask = pd.Series([True] * len(df))
            
            for field, condition in conditions.items():
                if field in df.columns:
                    if isinstance(condition, (list, tuple)):
                        mask &= df[field].isin(condition)
                    else:
                        mask &= (df[field] == condition)
            
            # Get matching packets
            matches = df[mask]
            
            if not matches.empty:
                print(f"Rule '{rule_name}' matched {len(matches)} packets")
                
                # Add alerts for matching packets (limit to first 10 for performance)
                for _, packet in matches.head(10).iterrows():
                    alert = {
                        'rule_name': rule_name,
                        'severity': rule['severity'],
                        'timestamp': packet['timestamp'],
                        'src_ip': packet['src_ip'],
                        'dst_ip': packet['dst_ip'],
                        'src_port': packet['src_port'],
                        'dst_port': packet['dst_port'],
                        'protocol': packet['protocol'],
                        'description': rule['description'],
                        'detection_method': 'rule-based'
                    }
                    analysis_results['alerts'].append(alert)
                
                # Update summary statistics
                analysis_results['summary']['total_alerts'] += len(matches)
                if rule_name not in analysis_results['summary']['attack_types']:
                    analysis_results['summary']['attack_types'][rule_name] = 0
                analysis_results['summary']['attack_types'][rule_name] += len(matches)
        
        print(f"Analysis completed. Found {analysis_results['summary']['total_alerts']} alerts")
        return analysis_results
        
    except Exception as e:
        print(f"Error in analyze_pcap: {str(e)}")
        return {
            'error': str(e),
            'status': 'failed'
        }

def generate_report(analysis_results):
    """Generate a formatted report from analysis results"""
    try:
        report = {
            'status': 'success',
            'data': analysis_results,
            'timestamp': pd.Timestamp.now().isoformat(),
            'summary_text': f"Analysis completed with {analysis_results.get('summary', {}).get('total_alerts', 0)} alerts detected from {analysis_results.get('summary', {}).get('total_packets', 0)} packets."
        }
        return json.dumps(report, indent=2, default=str)
    except Exception as e:
        return json.dumps({
            'error': f'Report generation failed: {str(e)}',
            'status': 'failed'
        }, indent=2)
