from scapy.all import *
import pandas as pd
import numpy as np

# Keep empty rules_list for backward compatibility if needed, 
# but we will switch to behavioral analysis.
rules_list = []

def detect_time_based_attacks(df):
    """
    Apply time-based behavioral detection rules based on the user provided table.
    Returns:
        - df: DataFrame with 'label' column updated (1 for attack)
        - alerts: List of alert dictionaries
        - stats: Dictionary of packet counts per rule
    """
    alerts = []
    stats = {}
    
    # Ensure timestamp is datetime
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
    df = df.sort_values('timestamp')
    
    # DEBUG: Print data stats
    print(f"DEBUG: Behavioral Analysis - {len(df)} packets")
    print(f"DEBUG: Time range: {df['timestamp'].min()} to {df['timestamp'].max()}")
    if 'protocol' in df.columns:
        print(f"DEBUG: Protocols: {df['protocol'].value_counts().to_dict()}")
    if 'flags' in df.columns:
        print(f"DEBUG: Sample Flags: {df['flags'].head().tolist()}")

    # Helper to check flags safely
    def has_flag(flags_str, flag_char):
        if not isinstance(flags_str, str): return False
        return flag_char in flags_str
        
    # Create masks for protocols
    is_tcp = df['protocol'] == 'TCP'
    is_udp = df['protocol'] == 'UDP'
    is_icmp = df['protocol'] == 'ICMP'
    
    syn_mask = is_tcp & df['flags'].apply(lambda x: has_flag(x, 'S') and not has_flag(x, 'A'))
    
    if syn_mask.any():
        syn_packets = df[syn_mask].copy()
        if not syn_packets.empty:
            syn_rates = syn_packets.set_index('timestamp').resample('1s')['packet_id'].count()
            
            rolling_syn_count = syn_rates.rolling('10s').sum()
            max_syn_10s = rolling_syn_count.max()
            print(f"DEBUG: Max SYN rate (10s window): {max_syn_10s/10:.2f} pps (Threshold: 500)")
            
            syn_threshold_sum = 500 * 10
            flood_windows = rolling_syn_count[rolling_syn_count > syn_threshold_sum]
            
            if not flood_windows.empty:
                max_pps = syn_rates.max()
                rule_name = 'TCP_SYN_Flood'
                alerts.append({
                    'rule_name': rule_name,
                    'severity': 'high',
                    'description': f'TCP SYN Flood detected (Peak rate: {max_pps} pps)',
                    'timestamp': str(flood_windows.index[0]),
                    'src_ip': 'Multiple',
                    'dst_ip': 'Target',
                    'src_port': 0,
                    'dst_port': 0,
                    'protocol': 'TCP',
                    'detection_method': 'behavioral'
                })
                attack_start = flood_windows.index.min()
                attack_end = flood_windows.index.max() + pd.Timedelta(seconds=10)
                window_mask = syn_mask & (df['timestamp'] >= attack_start) & (df['timestamp'] <= attack_end)
                df.loc[window_mask, 'label'] = 1
                stats[rule_name] = int(window_mask.sum())
                
    icmp_mask = is_icmp
    if icmp_mask.any():
        icmp_packets = df[icmp_mask].copy()
        icmp_rates = icmp_packets.set_index('timestamp').resample('1s')['packet_id'].count()
        rolling_icmp = icmp_rates.rolling('5s').sum()
        
        threshold_sum = 300 * 5
        flood_icmp = rolling_icmp[rolling_icmp > threshold_sum]
        if not flood_icmp.empty:
            max_pps = icmp_rates.max()
            rule_name = 'ICMP_Flood'
            first_ts = flood_icmp.index.min()
            last_ts = flood_icmp.index.max()
            alerts.append({
                'rule_name': rule_name,
                'severity': 'medium',
                'description': f'ICMP Flood detected (Peak rate: {max_pps} pps)',
                'timestamp': str(first_ts),
                'src_ip': 'Multiple',
                'dst_ip': 'Target',
                'src_port': 0,
                'dst_port': 0,
                'protocol': 'ICMP',
                'detection_method': 'behavioral'
            })
            window_mask = icmp_mask & (df['timestamp'] >= first_ts) & (df['timestamp'] <= last_ts + pd.Timedelta(seconds=5))
            df.loc[window_mask, 'label'] = 1
            stats[rule_name] = int(window_mask.sum())

    scan_mask = (is_tcp | is_udp)
    potential_scan = df[scan_mask].copy()
    
    port_counts = potential_scan.groupby(['src_ip', pd.Grouper(key='timestamp', freq='30s')])['dst_port'].nunique()
    scanners = port_counts[port_counts > 20]
    
    rule_name = 'Port_Scan'
    for (ip, time_bin), count in scanners.items():
        alerts.append({
            'rule_name': rule_name,
            'severity': 'medium',
            'description': f'Port Scan detected from {ip} (scanned {count} ports in 30s)',
            'timestamp': str(time_bin),
            'src_ip': ip,
            'dst_ip': 'Multiple',
            'src_port': 0,
            'dst_port': 0,
            'protocol': 'TCP/UDP',
            'detection_method': 'behavioral'
        })
        window_end = time_bin + pd.Timedelta(seconds=30)
        mask = scan_mask & (df['src_ip'] == ip) & (df['timestamp'] >= time_bin) & (df['timestamp'] < window_end)
        df.loc[mask, 'label'] = 1
        stats[rule_name] = stats.get(rule_name, 0) + int(mask.sum())

    http_mask = is_tcp & df['dst_port'].isin([80, 443])
    if http_mask.any():
        http_rates = df[http_mask].set_index('timestamp').resample('1s')['packet_id'].count()
        rolling_http = http_rates.rolling('10s').mean()
        flood_http = rolling_http[rolling_http > 200]
        if not flood_http.empty:
            top_src = df[http_mask]['src_ip'].mode().iloc[0] if not df[http_mask]['src_ip'].empty else 'Multiple'
            top_dst = df[http_mask]['dst_ip'].mode().iloc[0] if not df[http_mask]['dst_ip'].empty else 'Web Server'
            rule_name = 'HTTP_Flood'
            first_ts = flood_http.index.min()
            last_ts = flood_http.index.max()
            alerts.append({
                'rule_name': rule_name,
                'severity': 'medium',
                'description': f'HTTP/HTTPS Flood detected (Peak rate: {http_rates.max()} req/sec)',
                'timestamp': str(first_ts),
                'src_ip': top_src,
                'dst_ip': top_dst,
                'src_port': 0,
                'dst_port': 80,
                'protocol': 'TCP',
                'detection_method': 'behavioral'
            })
            window_mask = http_mask & (df['timestamp'] >= first_ts) & (df['timestamp'] <= last_ts + pd.Timedelta(seconds=10))
            df.loc[window_mask, 'label'] = 1
            stats[rule_name] = int(window_mask.sum())

    dns_mask = is_udp & (df['src_port'] == 53)
    if dns_mask.any():
        dns_rates = df[dns_mask].set_index('timestamp').resample('1s')['packet_id'].count()
        active_dns = dns_rates[dns_rates > 100]
        if not active_dns.empty:
            rule_name = 'DNS_Amplification_Suspect'
            first_ts = active_dns.index.min()
            last_ts = active_dns.index.max()
            alerts.append({
                'rule_name': rule_name,
                'severity': 'high',
                'description': f'DNS Amplification detected (Peak rate: {dns_rates.max()} pps)',
                'timestamp': str(first_ts),
                'src_ip': 'DNS Server',
                'dst_ip': 'Victim',
                'src_port': 53,
                'dst_port': 0,
                'protocol': 'UDP',
                'detection_method': 'behavioral'
            })
            window_mask = dns_mask & (df['timestamp'] >= first_ts) & (df['timestamp'] <= last_ts + pd.Timedelta(seconds=5))
            df.loc[window_mask, 'label'] = 1
            stats[rule_name] = int(window_mask.sum())

    ssh_mask = is_tcp & (df['dst_port'] == 22) & df['flags'].apply(lambda x: has_flag(x, 'S'))
    if ssh_mask.any():
        ssh_counts = df[ssh_mask].groupby(['src_ip', pd.Grouper(key='timestamp', freq='60s')])['packet_id'].count()
        ssh_attackers = ssh_counts[ssh_counts > 40]
        
        rule_name = 'SSH_Brute_Force_Suspect'
        for (ip, time_bin), count in ssh_attackers.items():
            alerts.append({
                'rule_name': rule_name,
                'severity': 'medium',
                'description': f'SSH Brute Force detected from {ip} ({count} attempts in 60s)',
                'timestamp': str(time_bin),
                'src_ip': ip,
                'dst_ip': 'Server',
                'src_port': 0,
                'dst_port': 22,
                'protocol': 'TCP',
                'detection_method': 'behavioral'
            })
            window_end = time_bin + pd.Timedelta(seconds=60)
            mask = ssh_mask & (df['src_ip'] == ip) & (df['timestamp'] >= time_bin) & (df['timestamp'] < window_end)
            df.loc[mask, 'label'] = 1
            stats[rule_name] = stats.get(rule_name, 0) + int(mask.sum())

    rdp_mask = is_tcp & (df['dst_port'] == 3389) & df['flags'].apply(lambda x: has_flag(x, 'S'))
    if rdp_mask.any():
        rdp_counts = df[rdp_mask].groupby(['src_ip', pd.Grouper(key='timestamp', freq='30s')])['packet_id'].count()
        rdp_attackers = rdp_counts[rdp_counts > 20]
        
        rule_name = 'RDP_Scan'
        for (ip, time_bin), count in rdp_attackers.items():
            alerts.append({
                'rule_name': rule_name,
                'severity': 'medium',
                'description': f'RDP Scan detected from {ip} ({count} attempts)',
                'timestamp': str(time_bin),
                'src_ip': ip,
                'dst_ip': 'Server',
                'src_port': 0,
                'dst_port': 3389,
                'protocol': 'TCP',
                'detection_method': 'behavioral'
            })
            window_end = time_bin + pd.Timedelta(seconds=30)
            mask = rdp_mask & (df['src_ip'] == ip) & (df['timestamp'] >= time_bin) & (df['timestamp'] < window_end)
            df.loc[mask, 'label'] = 1
            stats[rule_name] = stats.get(rule_name, 0) + int(mask.sum())

    smb_mask = is_tcp & df['dst_port'].isin([139, 445]) & df['flags'].apply(lambda x: has_flag(x, 'S'))
    if smb_mask.any():
        smb_counts = df[smb_mask].groupby(['src_ip', pd.Grouper(key='timestamp', freq='30s')])['packet_id'].count()
        smb_attackers = smb_counts[smb_counts > 30]
        
        rule_name = 'SMB_Scan'
        for (ip, time_bin), count in smb_attackers.items():
            alerts.append({
                'rule_name': rule_name,
                'severity': 'medium',
                'description': f'SMB Scan detected from {ip} ({count} attempts)',
                'timestamp': str(time_bin),
                'src_ip': ip,
                'dst_ip': 'Server',
                'src_port': 0,
                'dst_port': 445,
                'protocol': 'TCP',
                'detection_method': 'behavioral'
            })
            window_end = time_bin + pd.Timedelta(seconds=30)
            mask = smb_mask & (df['src_ip'] == ip) & (df['timestamp'] >= time_bin) & (df['timestamp'] < window_end)
            df.loc[mask, 'label'] = 1
            stats[rule_name] = stats.get(rule_name, 0) + int(mask.sum())
            
    bacnet_mask = is_udp & (df['dst_port'] == 47808)
    if bacnet_mask.any():
        bacnet_rates = df[bacnet_mask].set_index('timestamp').resample('1s')['packet_id'].count()
        if (bacnet_rates.rolling('15s').mean() > 50).any():
             rule_name = 'BACnet_Broadcast_Suspect'
             alerts.append({
                'rule_name': rule_name,
                'severity': 'medium',
                'description': 'High rate of BACnet traffic detected',
                'timestamp': str(bacnet_rates.index[0]),
                'src_ip': 'Multiple',
                'dst_ip': 'Broadcast',
                'src_port': 0,
                'dst_port': 47808,
                'protocol': 'UDP',
                'detection_method': 'behavioral'
            })
             df.loc[bacnet_mask, 'label'] = 1
             stats[rule_name] = int(bacnet_mask.sum())

    modbus_mask = is_tcp & (df['dst_port'] == 502)
    if modbus_mask.any():
        modbus_rates = df[modbus_mask].set_index('timestamp').resample('1s')['packet_id'].count()
        if (modbus_rates.rolling('20s').mean() > 30).any():
            rule_name = 'Modbus_TCP_Suspect'
            alerts.append({
                'rule_name': rule_name,
                'severity': 'medium',
                'description': 'High rate of Modbus TCP traffic detected',
                'timestamp': str(modbus_rates.index[0]),
                'src_ip': 'Multiple',
                'dst_ip': 'Target',
                'src_port': 0,
                'dst_port': 502,
                'protocol': 'TCP',
                'detection_method': 'behavioral'
            })
            df.loc[modbus_mask, 'label'] = 1
            stats[rule_name] = int(modbus_mask.sum())
            
    ntp_mask = is_udp & (df['src_port'] == 123)
    if ntp_mask.any():
        ntp_rates = df[ntp_mask].set_index('timestamp').resample('1s')['packet_id'].count()
        if (ntp_rates > 80).any():
            rule_name = 'NTP_Amplification_Suspect'
            alerts.append({
                'rule_name': rule_name,
                'severity': 'medium',
                'description': 'NTP Amplification detected',
                'timestamp': str(ntp_rates.index[0]),
                'src_ip': 'NTP Server',
                'dst_ip': 'Victim',
                'src_port': 123,
                'dst_port': 0,
                'protocol': 'UDP',
                'detection_method': 'behavioral'
            })
            df.loc[ntp_mask, 'label'] = 1
            stats[rule_name] = int(ntp_mask.sum())
            
    return df, alerts, stats
