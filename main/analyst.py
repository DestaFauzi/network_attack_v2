import pandas as pd
import json
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve, auc
import numpy as np
from scapy.all import rdpcap
import os
import sys

# Import rules_list from rules.py in the same directory
try:
    from .rules import rules_list, detect_time_based_attacks
except ImportError:
    # Fallback for direct execution
    from rules import rules_list, detect_time_based_attacks

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
                    # Format timestamp to human-readable string (YYYY-MM-DD HH:MM:SS.micros)
                    'timestamp': datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'protocol': 'Unknown',
                    'src_ip': 'Unknown',
                    'dst_ip': 'Unknown',
                    'src_port': 0,
                    'dst_port': 0,
                    'packet_length': len(packet),
                    'flags': ''  
                }
                
                # Extract IP layer information
                if packet.haslayer('IP'):
                    ip_layer = packet['IP']
                    row['src_ip'] = ip_layer.src
                    row['dst_ip'] = ip_layer.dst
                    row['protocol'] = str(ip_layer.proto)
                
                # Extract TCP layer information
                if packet.haslayer('TCP'):
                    tcp_layer = packet['TCP']
                    row['src_port'] = int(tcp_layer.sport)
                    row['dst_port'] = int(tcp_layer.dport)
                    row['flags'] = str(tcp_layer.flags)
                    row['protocol'] = 'TCP'
                
                # Extract UDP layer information
                elif packet.haslayer('UDP'):
                    udp_layer = packet['UDP']
                    row['src_port'] = int(udp_layer.sport)
                    row['dst_port'] = int(udp_layer.dport)
                    row['protocol'] = 'UDP'
                
                # Extract ICMP layer information
                elif packet.haslayer('ICMP'):
                    row['protocol'] = 'ICMP'
                
                data.append(row)
                
            except Exception as e:
                print(f"Error processing packet {i}: {str(e)}")
                continue
        
        df = pd.DataFrame(data)
        
        # Enforce data types to prevent "not supported between int and str" errors
        if not df.empty:
            df['protocol'] = df['protocol'].astype(str)
            df['flags'] = df['flags'].astype(str)
            df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0).astype(int)
            df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0).astype(int)
            df['packet_length'] = pd.to_numeric(df['packet_length'], errors='coerce').fillna(0).astype(int)
        
        print(f"Successfully converted {len(df)} packets to DataFrame")
        return df
        
    except Exception as e:
        raise Exception(f"Error converting PCAP to DataFrame: {str(e)}")

def analyze_dataframe(df, filename, file_size_bytes, output_path_prefix):
    """
    Analyze a DataFrame of packets (from one or multiple PCAP files).
    """
    try:
        if df.empty:
            return {
                'error': 'No packets found in data',
                'status': 'failed'
            }
        
        # Calculate file size string
        if file_size_bytes > 1024 * 1024:
            file_size_str = f"{file_size_bytes / (1024 * 1024):.2f} MB"
        elif file_size_bytes > 1024:
            file_size_str = f"{file_size_bytes / 1024:.2f} KB"
        else:
            file_size_str = f"{file_size_bytes} bytes"

        analysis_results = {
            'alerts': [],
            'summary': {
                'filename': filename,
                'file_size': file_size_str,
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
            'packet_sample': df.head(50).fillna('Unknown').to_dict(orient='records'),
            'status': 'success'
        }
        
        # Initialize label column for ML ground truth (0 = Normal, 1 = Attack)
        df['label'] = 0
        
        # Apply behavioral/time-based detection
        print("Running behavioral analysis...")
        df, time_based_alerts, rule_stats = detect_time_based_attacks(df)
        analysis_results['alerts'].extend(time_based_alerts)
        
        # Update summary with behavioral stats
        for rule_name, count in rule_stats.items():
            if rule_name not in analysis_results['summary']['attack_types']:
                analysis_results['summary']['attack_types'][rule_name] = 0
            analysis_results['summary']['attack_types'][rule_name] += count

        # Apply rule-based detection
        for rule in rules_list:
            rule_name = rule['name']
            conditions = rule['conditions']
            
            # Create a mask based on rule conditions
            mask = pd.Series([True] * len(df))
            
            for field, condition in conditions.items():
                if field in df.columns:
                    # Support list/tuple inclusion
                    if isinstance(condition, (list, tuple)):
                        mask &= df[field].isin(condition)
                    # Support comparison operators via dict: {'gt': X, 'lt': Y, 'range': (a,b), 'neq': Z}
                    elif isinstance(condition, dict):
                        try:
                            series = df[field]
                            if 'gt' in condition:
                                mask &= (series > condition['gt'])
                            if 'lt' in condition:
                                mask &= (series < condition['lt'])
                            if 'range' in condition and isinstance(condition['range'], (list, tuple)) and len(condition['range']) == 2:
                                low, high = condition['range']
                                mask &= series.between(low, high, inclusive='both')
                            if 'neq' in condition:
                                mask &= (series != condition['neq'])
                        except Exception:
                            # Fallback: ignore malformed condition
                            pass
                    else:
                        mask &= (df[field] == condition)
            
            # Get matching packets
            matches = df[mask]
            
            if not matches.empty:
                print(f"Rule '{rule_name}' matched {len(matches)} packets")
                
                # Mark these packets as attacks (Ground Truth for ML)
                df.loc[mask, 'label'] = 1
                
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
                # analysis_results['summary']['total_alerts'] += len(matches) # Don't sum here to avoid double counting
                if rule_name not in analysis_results['summary']['attack_types']:
                    analysis_results['summary']['attack_types'][rule_name] = 0
                analysis_results['summary']['attack_types'][rule_name] += len(matches)
        
        # Calculate total unique alerts (packets marked as attack)
        analysis_results['summary']['total_alerts'] = int(df['label'].sum())
        print(f"Total unique malicious packets detected: {analysis_results['summary']['total_alerts']}")
        
        # Save full packet data for pagination (Including Labels now)
        packets_csv_path = output_path_prefix + '_packets.csv'
        print(f"Saving full packet data to: {packets_csv_path}")
        df.fillna('Unknown').to_csv(packets_csv_path, index=False)
        analysis_results['packets_file'] = os.path.basename(packets_csv_path)
        
        # --- Random Forest Model Evaluation (Simulated using Rule-Based Labels) ---
        print("Training Random Forest model for performance metrics...")
        try:
            # Prepare Features (X)
            # Encode 'protocol' column
            le_proto = LabelEncoder()
            df['protocol_encoded'] = le_proto.fit_transform(df['protocol'].astype(str))
            
            # Encode 'flags' column (simple string to int mapping if possible, or just length/count)
            # For simplicity, use label encoding for flags
            le_flags = LabelEncoder()
            df['flags_encoded'] = le_flags.fit_transform(df['flags'].astype(str))
            
            # Select numerical features for the model
            feature_cols = ['src_port', 'dst_port', 'packet_length', 'protocol_encoded', 'flags_encoded']
            X = df[feature_cols].fillna(0)
            y = df['label'] # 0 or 1
            
            # Check if we have enough data and at least two classes for meaningful splitting
            # (If only one class exists, metrics like AUC/Recall might be trivial, but we calculate anyway)
            print(f"Class distribution: {y.value_counts().to_dict()}")
            
            if len(df) > 10:
                # Define ratios to test (Test Size: 0.2=80:20, 0.3=70:30, 0.4=60:40)
                test_sizes = [0.2, 0.3, 0.4]
                comparison_data = []
                primary_results = {}
                
                # Iterate through different split ratios
                for ts in test_sizes:
                    # Calculate ratio label (e.g., "80:20")
                    # Use round() to handle floating point precision issues (e.g. 0.3 * 100 = 29.999...)
                    ratio_label = f"{int(round((1-ts)*100))}:{int(round(ts*100))}"
                    
                    # Split data
                    stratify_param = None
                    if y.value_counts().min() >= 2:
                        stratify_param = y
                    
                    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=ts, random_state=42, stratify=stratify_param)
                    
                    # Train Model
                    rf = RandomForestClassifier(n_estimators=10, random_state=42)
                    rf.fit(X_train, y_train)
                    
                    # Predict
                    y_pred = rf.predict(X_test)
                    
                    # Calculate Metrics
                    acc = accuracy_score(y_test, y_pred)
                    prec = precision_score(y_test, y_pred, zero_division=0)
                    rec = recall_score(y_test, y_pred, zero_division=0)
                    f1 = f1_score(y_test, y_pred, zero_division=0)
                    
                    # Add to comparison list
                    comparison_data.append({
                        'ratio': ratio_label,
                        'accuracy': float(f"{acc:.4f}"),
                        'precision': float(f"{prec:.4f}"),
                        'recall': float(f"{rec:.4f}"),
                        'f1_score': float(f"{f1:.4f}")
                    })
                    
                    # If this is the standard 70:30 split (ts=0.3), capture detailed results for main dashboard
                    if ts == 0.3:
                        # Confusion Matrix
                        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
                        cm_list = cm.tolist()
                        
                        # Feature Importance
                        importances = rf.feature_importances_
                        feature_importance_list = [
                            {'feature': col, 'importance': float(imp)}
                            for col, imp in zip(feature_cols, importances)
                        ]
                        feature_importance_list.sort(key=lambda x: x['importance'], reverse=True)
                        
                        # ROC Curve
                        roc_data = None
                        try:
                            if len(np.unique(y_test)) == 2:
                                y_score = rf.predict_proba(X_test)[:, 1]
                                fpr, tpr, _ = roc_curve(y_test, y_score)
                                roc_auc = auc(fpr, tpr)
                                if len(fpr) > 100:
                                    indices = np.linspace(0, len(fpr) - 1, 100).astype(int)
                                    fpr = fpr[indices]
                                    tpr = tpr[indices]
                                roc_data = {
                                    'fpr': fpr.tolist(),
                                    'tpr': tpr.tolist(),
                                    'auc': float(f"{roc_auc:.4f}")
                                }
                        except Exception:
                            pass
                            
                        primary_results = {
                            'accuracy': float(f"{acc:.4f}"),
                            'precision': float(f"{prec:.4f}"),
                            'recall': float(f"{rec:.4f}"),
                            'f1_score': float(f"{f1:.4f}"),
                            'confusion_matrix': cm_list,
                            'feature_importance': feature_importance_list,
                            'class_distribution': y.value_counts().to_dict(),
                            'roc_data': roc_data,
                            'train_size': len(X_train),
                            'test_size': len(X_test),
                            'status': 'success'
                        }

                # Attach comparison data to results
                primary_results['split_comparison'] = comparison_data
                analysis_results['ml_performance'] = primary_results

            else:
                analysis_results['ml_performance'] = {
                    'error': 'Not enough data points for ML evaluation',
                    'status': 'skipped'
                }
                
        except Exception as e:
            print(f"Error in ML evaluation: {e}")
            analysis_results['ml_performance'] = {
                'error': str(e),
                'status': 'failed'
            }
        
        print(f"Analysis completed. Found {analysis_results['summary']['total_alerts']} alerts")
        return analysis_results
        
    except Exception as e:
        print(f"Error in analyze_dataframe: {str(e)}")
        return {
            'error': str(e),
            'status': 'failed'
        }

def analyze_pcap(file_path):
    """Analyze PCAP file for network attacks"""
    try:
        print(f"Starting analysis of: {file_path}")
        
        # Check if file exists
        if not os.path.exists(file_path):
            raise Exception(f"File not found: {file_path}")
        
        # Convert PCAP to DataFrame
        df = pcap_to_dataframe(file_path)
        
        file_size_bytes = os.path.getsize(file_path)
        
        return analyze_dataframe(df, os.path.basename(file_path), file_size_bytes, file_path)
        
    except Exception as e:
        print(f"Error in analyze_pcap: {str(e)}")
        return {
            'error': str(e),
            'status': 'failed'
        }

def analyze_multiple_pcaps(file_paths, output_filename_prefix):
    """
    Analyze multiple PCAP files by aggregating them into a single dataset.
    
    Args:
        file_paths (list): List of absolute paths to PCAP files.
        output_filename_prefix (str): Prefix for the output CSV file (e.g. combined_timestamp).
    """
    try:
        print(f"Starting aggregated analysis of {len(file_paths)} files")
        
        dfs = []
        total_size_bytes = 0
        
        for file_path in file_paths:
            if not os.path.exists(file_path):
                print(f"Warning: File not found: {file_path}")
                continue
                
            print(f"Processing file: {file_path}")
            df = pcap_to_dataframe(file_path)
            if not df.empty:
                dfs.append(df)
            
            total_size_bytes += os.path.getsize(file_path)
            
        if not dfs:
             return {
                'error': 'No valid packets found in any of the uploaded files',
                'status': 'failed'
            }
            
        # Combine all DataFrames
        print("Combining DataFrames...")
        combined_df = pd.concat(dfs, ignore_index=True)
        
        # Ensure timestamp is datetime and sort
        if 'timestamp' in combined_df.columns:
             combined_df['timestamp'] = pd.to_datetime(combined_df['timestamp'])
             combined_df = combined_df.sort_values('timestamp')
             # Convert back to string for consistency if needed, but detect_time_based_attacks handles datetime
             # We might want to keep it as datetime for analysis, then format for display if needed.
             # pcap_to_dataframe returns string. detect_time_based_attacks converts to datetime.
        
        # Create a virtual filename for the report
        combined_filename = f"Aggregated Report ({len(file_paths)} files)"
        
        return analyze_dataframe(combined_df, combined_filename, total_size_bytes, output_filename_prefix)

    except Exception as e:
        print(f"Error in analyze_multiple_pcaps: {str(e)}")
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
