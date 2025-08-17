import pandas as pd
from rules import rules_list
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import numpy as np
def analyze_pcap(file_path):
    try:
        # Read the uploaded PCAP data (assuming it's been converted to CSV format)
        df = pd.read_csv(file_path)
        
        # Initialize results dictionary
        analysis_results = {
            'alerts': [],
            'summary': {
                'total_packets': len(df),
                'total_alerts': 0,
                'attack_types': {},
                'ml_predictions': {}
            }
        }
        
        # Prepare data for Random Forest
        feature_columns = ['protocol', 'src_port', 'dst_port', 'packet_length']
        label_encoders = {}
        
        # Encode categorical features
        X = df[feature_columns].copy()
        for column in X.select_dtypes(include=['object']):
            label_encoders[column] = LabelEncoder()
            X[column] = label_encoders[column].fit_transform(X[column])
            
        # Initialize and train Random Forest model
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # Apply rule-based detection
        for rule in rules_list:
            rule_name = rule['name']
            conditions = rule['conditions']
            
            # Create a mask based on rule conditions
            mask = pd.Series([True] * len(df))
            for field, condition in conditions.items():
                if isinstance(condition, (list, tuple)):
                    mask &= df[field].isin(condition)
                else:
                    mask &= (df[field] == condition)
            
            # Get matching packets
            matches = df[mask]
            
            if not matches.empty:
                # Add alerts for matching packets
                for _, packet in matches.iterrows():
                    alert = {
                        'rule_name': rule_name,
                        'severity': rule['severity'],
                        'timestamp': packet['timestamp'] if 'timestamp' in packet else None,
                        'src_ip': packet['src_ip'] if 'src_ip' in packet else None,
                        'dst_ip': packet['dst_ip'] if 'dst_ip' in packet else None,
                        'protocol': packet['protocol'] if 'protocol' in packet else None,
                        'description': rule['description'],
                        'detection_method': 'rule-based'
                    }
                    analysis_results['alerts'].append(alert)
                
                # Update summary statistics
                analysis_results['summary']['total_alerts'] += len(matches)
                if rule_name not in analysis_results['summary']['attack_types']:
                    analysis_results['summary']['attack_types'][rule_name] = 0
                analysis_results['summary']['attack_types'][rule_name] += len(matches)
        
        # Apply Random Forest detection
        predictions = rf_model.predict(X)
        prediction_proba = rf_model.predict_proba(X)
        
        # Add ML-based alerts for suspicious packets
        for idx, (pred, prob) in enumerate(zip(predictions, prediction_proba)):
            if prob.max() > 0.8:  # High confidence threshold
                packet = df.iloc[idx]
                alert = {
                    'rule_name': 'ML_Detection',
                    'severity': 'medium',
                    'timestamp': packet['timestamp'] if 'timestamp' in packet else None,
                    'src_ip': packet['src_ip'] if 'src_ip' in packet else None,
                    'dst_ip': packet['dst_ip'] if 'dst_ip' in packet else None,
                    'protocol': packet['protocol'] if 'protocol' in packet else None,
                    'description': f'Anomaly detected by Random Forest (confidence: {prob.max():.2f})',
                    'detection_method': 'machine-learning'
                }
                analysis_results['alerts'].append(alert)
                analysis_results['summary']['total_alerts'] += 1
        
        # Add ML summary statistics
        analysis_results['summary']['ml_predictions'] = {
            'total_anomalies': sum(predictions == 1),
            'confidence_scores': {
                'min': float(prediction_proba.max(axis=1).min()),
                'max': float(prediction_proba.max(axis=1).max()),
                'mean': float(prediction_proba.max(axis=1).mean())
            }
        }
        
        return analysis_results
        
    except Exception as e:
        return {
            'error': str(e),
            'status': 'failed'
        }

def generate_report(analysis_results):
    """Generate a formatted report from analysis results"""
    report = {
        'status': 'success',
        'data': analysis_results,
        'timestamp': pd.Timestamp.now().isoformat()
    }
    return json.dumps(report, indent=2)
