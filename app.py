from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from datetime import datetime
import os
import sys
import secrets
import psutil

# Add main directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'main'))

# Import analyst functions
from main.analyst import analyze_pcap, generate_report

# Import authentication functions
from login_live_monitoring import require_auth, LiveMonitoringAuth
from config import get_default_interface

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.secret_key = 'your-secret-key-here'  # Add secret key for sessions

# Initialize auth manager
# Hapus baris ini:
# auth_manager = LiveMonitoringAuth()

# Ganti dengan import:
from login_live_monitoring import auth_manager

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/main/analyst', methods=['GET', 'POST'])
def upload_pcap():
    if request.method == 'GET':
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            # Check if file was uploaded
            if 'pcapFile' not in request.files:
                return jsonify({'error': 'No file uploaded', 'status': 'failed'}), 400
            
            file = request.files['pcapFile']
            
            # Check if file is selected
            if file.filename == '':
                return jsonify({'error': 'No file selected', 'status': 'failed'}), 400
            
            # Check file extension
            if not file.filename.lower().endswith(('.pcap', '.pcapng')):
                return jsonify({'error': 'Invalid file format. Only .pcap and .pcapng files are allowed.', 'status': 'failed'}), 400
            
            # Create uploads directory if it doesn't exist
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            # Generate unique filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{file.filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Save file
            file.save(filepath)
            
            # Analyze the pcap file
            print(f"Starting analysis of: {filepath}")
            analysis_result = analyze_pcap(filepath)
            
            if analysis_result:
                # Generate report
                report_data = generate_report(analysis_result, filename)
                
                return jsonify({
                    'message': 'File uploaded and analyzed successfully',
                    'filename': filename,
                    'analysis': analysis_result,
                    'report': report_data,
                    'status': 'success'
                })
            else:
                return jsonify({'error': 'Analysis failed - no results generated', 'status': 'failed'}), 500
                
        except Exception as e:
            print(f"Error during analysis: {str(e)}")
            return jsonify({'error': f'Analysis failed: {str(e)}', 'status': 'failed'}), 500
    
    return jsonify({'error': 'Method not allowed', 'status': 'failed'}), 405

@app.route('/api/data')
def get_data():
    # API endpoint for getting analysis data
    data = {
        'timestamp': datetime.now().strftime('%d-%m-%Y %H:%M:%S'),
        'status': 'active'
    }
    return jsonify(data)

# Monitoring API endpoints
@app.route('/api/monitoring/start', methods=['POST'])
@require_auth('control')
def start_monitoring():
    try:
        # Import monitoring functionality dengan nama yang benar
        from real_time_alerts import start_live_monitoring
        
        # Get interface dari request atau gunakan default
        # Handle both JSON and non-JSON requests
        try:
            data = request.get_json() or {}
        except:
            data = {}  # Fallback jika JSON parsing gagal
            
        interface = data.get('interface') or get_default_interface()
        
        # Start monitoring menggunakan fungsi yang sudah ada
        result = start_live_monitoring(interface)
        
        if result.get('status') == 'started':
            return jsonify({
                'status': 'started',
                'interface': result.get('interface', interface),
                'message': 'Monitoring started successfully'
            })
        elif result.get('status') == 'already_running':
            return jsonify({
                'status': 'already_running',
                'interface': interface,
                'message': 'Monitoring is already running'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': result.get('message', 'Failed to start monitoring')
            }), 500
            
    except ImportError as e:
        return jsonify({
            'status': 'error',
            'message': f'Monitoring module not available: {str(e)}'
        }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to start monitoring: {str(e)}'
        }), 500

@app.route('/api/monitoring/stop', methods=['POST'])
@require_auth('configure')
def stop_monitoring():
    try:
        from real_time_alerts import stop_live_monitoring
        
        result = stop_live_monitoring()
        
        return jsonify({
            'status': 'stopped',
            'message': 'Monitoring stopped successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to stop monitoring: {str(e)}'
        }), 500

@app.route('/api/monitoring/status', methods=['GET'])
@require_auth('view')
def monitoring_status():
    try:
        from real_time_alerts import get_monitoring_status
        
        status = get_monitoring_status()
        default_interface = get_default_interface()
        
        return jsonify({
            'is_monitoring': status.get('is_monitoring', False),
            'interface': status.get('interface') or default_interface or "Ethernet",
            'total_packets': status.get('total_packets', 0),
            'total_alerts': status.get('alerts_count', 0),
            'uptime': status.get('uptime', 0),
            'start_time': status.get('start_time')
        })
    except Exception as e:
        # Fallback response jika ada error
        return jsonify({
            'is_monitoring': False,
            'interface': "Ethernet",
            'total_packets': 0,
            'total_alerts': 0,
            'uptime': 0,
            'start_time': None
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/monitoring/statistics', methods=['GET'])
@require_auth('view')
def monitoring_statistics():
    try:
        # Return monitoring statistics
        return jsonify({
            'protocols': {
                'TCP': 0,
                'UDP': 0,
                'ICMP': 0,
                'Other': 0
            },
            'packet_rate': 0,
            'top_sources': {}
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/monitoring/alerts', methods=['GET'])
@require_auth('view')
def monitoring_alerts():
    try:
        # Return recent alerts
        return jsonify({
            'alerts': []
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/monitoring/logs', methods=['GET'])
@require_auth('view')
def monitoring_logs():
    try:
        from real_time_alerts import monitor
        
        # Get recent network logs/packets
        logs = monitor.get_recent_packets() if hasattr(monitor, 'get_recent_packets') else []
        
        return jsonify({
            'logs': logs,
            'count': len(logs)
        })
    except Exception as e:
        return jsonify({
            'logs': [],
            'count': 0,
            'error': str(e)
        })

@app.route('/api/ssh/generate-key', methods=['POST'])
@require_auth('configure')
def generate_ssh_key():
    data = request.get_json()
    username = data.get('username')
    key_name = data.get('key_name')
    
    if not username:
        return jsonify({'error': 'Username required'}), 400
    
    result = auth_manager.generate_ssh_key_pair(username, key_name)
    
    if result['success']:
        # Return private key content for download
        with open(result['private_key_path'], 'r') as f:
            private_key_content = f.read()
        
        return jsonify({
            'success': True,
            'key_name': result['key_name'],
            'public_key': result['public_key'],
            'private_key': private_key_content,
            'fingerprint': result['fingerprint']
        })
    else:
        return jsonify(result), 400

@app.route('/api/ssh/authenticate', methods=['POST'])
def ssh_authenticate():
    data = request.get_json()
    username = data.get('username')
    private_key = data.get('private_key')
    ip_address = request.remote_addr
    
    if not username or not private_key:
        return jsonify({'error': 'Username and private key required'}), 400
    
    result = auth_manager.authenticate_with_ssh_key(username, private_key, ip_address)
    
    if result['success']:
        session['session_id'] = result['session_id']
        return jsonify(result)
    else:
        return jsonify(result), 401

@app.route('/api/ssh/keys/<username>')
@require_auth('view')
def get_user_ssh_keys(username):
    keys = auth_manager.get_user_ssh_keys(username)
    return jsonify({'keys': keys})

@app.route('/api/ssh/revoke', methods=['POST'])
@require_auth('configure')
def revoke_ssh_key():
    data = request.get_json()
    username = data.get('username')
    key_name = data.get('key_name')
    
    if not username or not key_name:
        return jsonify({'error': 'Username and key name required'}), 400
    
    result = auth_manager.revoke_ssh_key(username, key_name)
    return jsonify(result)

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        server_ip = data.get('server_ip')  # Optional for remote authentication
        auth_method = data.get('auth_method', 'password')  # 'password' or 'ssh_key'
        
        if not username:
            return jsonify({
                'success': False,
                'message': 'Username is required'
            }), 400
        
        # Get client IP
        ip_address = request.remote_addr
        
        # Handle SSH key authentication
        if auth_method == 'ssh_key':
            private_key = data.get('private_key')
            if not private_key:
                return jsonify({
                    'success': False,
                    'message': 'Private key is required for SSH authentication'
                }), 400
            
            result = auth_manager.authenticate_with_ssh_key(username, private_key, ip_address)
            
            if result['success']:
                session['session_id'] = result['session_id']
                return jsonify({
                    'success': True,
                    'message': 'SSH authentication successful',
                    'redirect': '/live_dashboard',
                    'session_id': result['session_id']
                })
            else:
                return jsonify({
                    'success': False,
                    'message': result.get('message', 'SSH authentication failed')
                }), 401
        
        # Handle password authentication
        if not password:
            return jsonify({
                'success': False,
                'message': 'Password is required'
            }), 400
        
        # Authenticate user
        result = auth_manager.authenticate(username, password, ip_address, server_ip)
        
        if result['success']:
            # Store session
            session['session_id'] = result['session_id']
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'redirect': '/live_dashboard',
                'session_id': result['session_id']
            })
        else:
            return jsonify({
                'success': False,
                'message': result.get('message', 'Authentication failed')
            }), 401
            
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Login error: {str(e)}'
        }), 500

@app.route('/live_dashboard')
@require_auth('view')
def live_dashboard():
    return render_template('live_dashboard.html')

@app.route('/logout', methods=['POST'])
def logout():
    try:
        session_id = session.get('session_id')
        if session_id:
            auth_manager.logout(session_id)
            session.pop('session_id', None)
        
        return jsonify({
            'success': True,
            'redirect': '/login.html'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Debug endpoint untuk memeriksa status IP dan reset failed attempts
@app.route('/debug/auth-status', methods=['GET'])
def debug_auth_status():
    try:
        ip_address = request.remote_addr
        is_blocked = auth_manager._is_ip_blocked(ip_address)
        failed_attempts = auth_manager.failed_attempts.get(ip_address, [])
        
        return jsonify({
            'ip_address': ip_address,
            'is_blocked': is_blocked,
            'failed_attempts_count': len(failed_attempts),
            'failed_attempts': [attempt.isoformat() for attempt in failed_attempts],
            'active_sessions': list(auth_manager.active_sessions.keys()),
            'default_credentials': {
                'admin': 'admin123',
                'monitor': 'monitor123'
            },
            'users_in_system': list(auth_manager.users.keys())
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug/reset-ip', methods=['POST'])
def debug_reset_ip():
    try:
        ip_address = request.remote_addr
        if ip_address in auth_manager.failed_attempts:
            del auth_manager.failed_attempts[ip_address]
        
        return jsonify({
            'success': True,
            'message': f'Failed attempts reset for IP {ip_address}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug/test-auth', methods=['POST'])
def debug_test_auth():
    try:
        data = request.get_json()
        username = data.get('username', 'admin')
        password = data.get('password', 'admin123')
        ip_address = request.remote_addr
        
        # Test authentication directly
        result = auth_manager.authenticate(username, password, ip_address)
        
        return jsonify({
            'auth_result': result,
            'ip_address': ip_address,
            'is_blocked': auth_manager._is_ip_blocked(ip_address),
            'failed_attempts': len(auth_manager.failed_attempts.get(ip_address, []))
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug/test-ssh', methods=['POST'])
def debug_test_ssh():
    try:
        data = request.get_json()
        server_ip = data.get('server_ip')
        username = data.get('username')
        password = data.get('password')
        
        if not all([server_ip, username, password]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Test SSH connection directly
        result = auth_manager.authenticate_remote_server(username, password, server_ip)
        
        return jsonify({
            'ssh_test_result': result,
            'server_ip': server_ip,
            'username': username
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
