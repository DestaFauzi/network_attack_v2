from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response, send_file
from datetime import datetime
import os
import sys
import secrets
import psutil
import json
import pandas as pd
from dotenv import load_dotenv

# Add main directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'main'))

# Import analyst functions
from main.analyst import analyze_pcap, generate_report, analyze_multiple_pcaps

# Import authentication functions
from login_live_monitoring import require_auth, LiveMonitoringAuth
from config import get_default_interface

# Import Database Models
from models import db, PcapFile, Alert

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2GB max request size (to support multiple large files)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@127.0.0.1:3306/network_attack_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize DB
db.init_app(app)

# Auto-migration for analysis_json column
with app.app_context():
    try:
        from sqlalchemy import text
        # Try to select the column to see if it exists
        db.session.execute(text('SELECT analysis_json FROM uploads LIMIT 1'))
    except Exception:
        # If it fails, try to add the column
        try:
            db.session.rollback()
            print("Adding analysis_json column to uploads table...")
            # MySQL syntax
            db.session.execute(text('ALTER TABLE uploads ADD COLUMN analysis_json LONGTEXT'))
            db.session.commit()
        except Exception as e:
            print(f"Migration warning: {e}")

load_dotenv()
app.secret_key = os.getenv('SECRET_KEY', 'change-this-secret')

# Initialize auth manager
# Hapus baris ini:
# auth_manager = LiveMonitoringAuth()

# Ganti dengan import:
from login_live_monitoring import auth_manager

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/guide')
def guide():
    return render_template('guide.html')

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

@app.route('/api/ai/recommendations', methods=['POST'])
def ai_recommendations():
    try:
        payload = request.get_json() or {}
        analysis = payload.get('analysis') or payload.get('analysis_results') or {}
        from ai_recommendations import generate_ai_recommendations
        result = generate_ai_recommendations(analysis)
        
        # Include diagnostic message if present
        response = {
            'status': 'success' if result.get('status') == 'success' else 'error',
            'recommendations': result.get('recommendations', []),
            'message': result.get('message')
        }
        return jsonify(response)
    except Exception as e:
        # Jika terjadi exception fatal di tingkat route
        return jsonify({
            'status': 'error', 
            'message': str(e), 
            'recommendations': [
                'Enable SIEM correlation for detected attack types and top source IPs',
                'Harden exposed services and apply rate limiting on suspected endpoints',
                'Increase monitoring for protocols with highest anomaly counts',
                'Segment network to isolate frequently targeted destinations',
            ]
        }), 200

# Proxy endpoint: generate raw AI text from prompt (keeps API key di server)
@app.route('/api/ai/generate', methods=['POST'])
def ai_generate():
    try:
        payload = request.get_json() or {}
        prompt = payload.get('prompt', '').strip()
        if not prompt:
            return jsonify({'status': 'error', 'message': 'Missing prompt', 'text': ''}), 400

        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            return jsonify({'status': 'error', 'message': 'Missing GEMINI_API_KEY', 'text': ''}), 200

        # Reuse Gemini caller to keep logic consistent, with diagnostics
        try:
            from ai_recommendations import _call_gemini_with_diag as caller
        except Exception:
            from ai_recommendations import _call_gemini as caller

        result = caller(prompt, api_key)

        # If legacy caller is used, it returns a string
        if isinstance(result, str):
            text = result
            if text:
                return jsonify({'status': 'success', 'text': text})
            else:
                return jsonify({'status': 'success', 'text': '', 'message': 'empty_text'}), 200

        # Diagnostics-aware response
        text = result.get('text', '')
        if text:
            return jsonify({'status': 'success', 'text': text, 'diag': result})
        else:
            return jsonify({'status': 'success', 'text': '', 'message': 'empty_text', 'diag': result}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e), 'text': ''}), 200

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/history')
def history_page():
    return render_template('history.html')

@app.route('/api/db/history')
def get_db_history():
    try:
        # Fetch uploads sorted by newest first
        uploads = PcapFile.query.order_by(PcapFile.upload_time.desc()).all()
        return jsonify({
            'status': 'success',
            'data': [u.to_dict() for u in uploads]
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/db/report/<int:upload_id>')
def get_db_report(upload_id):
    try:
        upload = PcapFile.query.get_or_404(upload_id)
        
        # Check if full analysis JSON is stored
        if upload.analysis_json:
            analysis_result = json.loads(upload.analysis_json)
        else:
            # Fallback: Try to re-analyze if file exists
            # Handle both single file path and JSON list of paths (batch upload)
            is_batch = upload.filepath.strip().startswith('[') and ']' in upload.filepath
            
            if os.path.exists(upload.filepath) or is_batch:
                try:
                    print(f"Re-analyzing {upload.filepath} for full report...")
                    
                    if is_batch:
                        try:
                            file_paths = json.loads(upload.filepath)
                            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
                            output_prefix = os.path.join(app.config['UPLOAD_FOLDER'], f"reanalysis_{timestamp_str}_batch_{upload.id}")
                            analysis_result = analyze_multiple_pcaps(file_paths, output_prefix)
                        except json.JSONDecodeError:
                            # Fallback if not valid JSON but looks like a list
                            analysis_result = analyze_pcap(upload.filepath)
                    else:
                        # Re-run analysis to get full data (packet samples, ML metrics)
                        analysis_result = analyze_pcap(upload.filepath)
                    
                    # Update DB with full JSON for future
                    # Limit alerts in JSON to prevent performance issues (keep top 5000)
                    json_analysis = analysis_result.copy()
                    if len(json_analysis.get('alerts', [])) > 5000:
                         json_analysis['alerts'] = json_analysis['alerts'][:5000]

                    upload.analysis_json = json.dumps(json_analysis, default=str)
                    
                    # Update summary fields in case they changed
                    upload.file_size = analysis_result.get('summary', {}).get('file_size', upload.file_size)
                    upload.total_packets = analysis_result.get('summary', {}).get('total_packets', upload.total_packets)
                    upload.malicious_packets = analysis_result.get('summary', {}).get('total_alerts', upload.malicious_packets)
                    
                    # Update Alerts table: Delete old, Insert new (bulk - limit to 5000 to prevent MySQL timeouts/crashes)
                    try:
                        Alert.query.filter_by(upload_id=upload.id).delete()
                        
                        alerts_list = analysis_result.get('alerts', [])
                        if len(alerts_list) > 5000:
                            alerts_list = alerts_list[:5000]
                            
                        if alerts_list:
                             alert_mappings = []
                             for alert in alerts_list:
                                 alert_mappings.append({
                                     'upload_id': upload.id,
                                     'rule_name': alert.get('rule_name'),
                                     'severity': alert.get('severity'),
                                     'description': alert.get('description'),
                                     'timestamp': alert.get('timestamp'),
                                     'src_ip': alert.get('src_ip'),
                                     'dst_ip': alert.get('dst_ip'),
                                     'src_port': alert.get('src_port'),
                                     'dst_port': alert.get('dst_port'),
                                     'protocol': alert.get('protocol'),
                                     'detection_method': alert.get('detection_method')
                                 })
                             db.session.bulk_insert_mappings(Alert, alert_mappings)
                    except Exception as alert_err:
                        print(f"Warning: Failed to update Alert table: {alert_err}")
                        # Don't fail the whole request if Alert table update fails, 
                        # analysis_json is enough for dashboard.

                    db.session.commit()
                except Exception as e:
                    print(f"Re-analysis failed: {e}")
                    # Fallback to partial reconstruction
                    alerts = Alert.query.filter_by(upload_id=upload_id).all()
                    alerts_data = [a.to_dict() for a in alerts]
                    attack_types = {}
                    for a in alerts:
                        rule = a.rule_name
                        attack_types[rule] = attack_types.get(rule, 0) + 1
                    
                    analysis_result = {
                        'file_info': {
                            'filename': upload.filename,
                            'size': upload.file_size,
                            'total_packets': upload.total_packets
                        },
                        'summary': {
                            'total_alerts': upload.malicious_packets,
                            'attack_types': attack_types
                        },
                        'alerts': alerts_data
                    }
            else:
                # Fallback to partial reconstruction
                alerts = Alert.query.filter_by(upload_id=upload_id).all()
                alerts_data = [a.to_dict() for a in alerts]
                attack_types = {}
                for a in alerts:
                    rule = a.rule_name
                    attack_types[rule] = attack_types.get(rule, 0) + 1
                
                analysis_result = {
                    'file_info': {
                        'filename': upload.filename,
                        'size': upload.file_size,
                        'total_packets': upload.total_packets
                    },
                    'summary': {
                        'total_alerts': upload.malicious_packets,
                        'attack_types': attack_types
                    },
                    'alerts': alerts_data
                }
        
        report_data = generate_report(analysis_result)
        
        return jsonify({
            'status': 'success',
            'filename': upload.filename,
            'analysis': analysis_result,
            'report': report_data
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/main/analyst', methods=['GET', 'POST'])
def upload_pcap():
    if request.method == 'GET':
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            # Check if file was uploaded
            if 'pcapFile' not in request.files:
                return jsonify({'error': 'No file uploaded', 'status': 'failed'}), 400
            
            files = request.files.getlist('pcapFile')
            
            # Check if any file is selected
            if not files or files[0].filename == '':
                return jsonify({'error': 'No file selected', 'status': 'failed'}), 400
            
            # Create uploads directory if it doesn't exist
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            saved_paths = []
            filenames = []
            
            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            for file in files:
                # Check file extension
                if not file.filename.lower().endswith(('.pcap', '.pcapng')):
                    continue # Skip invalid files
                
                # Generate unique filename with timestamp
                filename = f"{timestamp_str}_{file.filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # Save file
                file.save(filepath)
                saved_paths.append(filepath)
                filenames.append(file.filename)
            
            if not saved_paths:
                 return jsonify({'error': 'No valid .pcap/.pcapng files uploaded', 'status': 'failed'}), 400

            # Analyze based on count
            if len(saved_paths) == 1:
                filepath = saved_paths[0]
                print(f"Starting analysis of: {filepath}")
                analysis_result = analyze_pcap(filepath)
                final_filename = filenames[0]
                final_filepath = filepath
            else:
                print(f"Starting batch analysis of {len(saved_paths)} files")
                # Use the first file's timestamp/prefix for the combined output
                output_prefix = os.path.join(app.config['UPLOAD_FOLDER'], f"{timestamp_str}_batch_combined")
                analysis_result = analyze_multiple_pcaps(saved_paths, output_prefix)
                final_filename = f"Batch Analysis ({len(saved_paths)} files): {', '.join(filenames[:3])}{'...' if len(filenames) > 3 else ''}"
                # Store list of paths as JSON string
                final_filepath = json.dumps(saved_paths)
            
            if analysis_result:
                # Generate report
                report_data = generate_report(analysis_result)

                # --- DATABASE INTEGRATION START ---
                try:
                    # 1. Create PcapFile record
                    # Create a copy for JSON storage to avoid modifying the original
                    json_analysis = analysis_result.copy()
                    # Limit alerts in JSON to prevent performance issues (keep top 5000)
                    if len(json_analysis.get('alerts', [])) > 5000:
                         json_analysis['alerts'] = json_analysis['alerts'][:5000]

                    pcap_entry = PcapFile(
                        filename=final_filename,
                        filepath=final_filepath,
                        file_size=analysis_result.get('summary', {}).get('file_size', '0 MB'),
                        total_packets=analysis_result.get('summary', {}).get('total_packets', 0),
                        malicious_packets=analysis_result.get('summary', {}).get('total_alerts', 0),
                        status='Success',
                        analysis_json=json.dumps(json_analysis, default=str)
                    )
                    db.session.add(pcap_entry)
                    db.session.flush() # Get ID before commit

                    # 2. Save Alerts (Bulk Insert for performance - limit to 5000 to prevent MySQL timeouts/crashes)
                    alerts_list = analysis_result.get('alerts', [])
                    if len(alerts_list) > 5000:
                        print(f"Limiting Alert table inserts to 5000 (total was {len(alerts_list)}) to prevent database crash.")
                        alerts_list = alerts_list[:5000]
                        
                    if alerts_list:
                        alert_mappings = []
                        for alert in alerts_list:
                            alert_mappings.append({
                                'upload_id': pcap_entry.id,
                                'rule_name': alert.get('rule_name'),
                                'severity': alert.get('severity'),
                                'description': alert.get('description'),
                                'timestamp': alert.get('timestamp'),
                                'src_ip': alert.get('src_ip'),
                                'dst_ip': alert.get('dst_ip'),
                                'src_port': alert.get('src_port'),
                                'dst_port': alert.get('dst_port'),
                                'protocol': alert.get('protocol'),
                                'detection_method': alert.get('detection_method')
                            })
                        
                        # Use bulk_insert_mappings for better performance with large datasets
                        db.session.bulk_insert_mappings(Alert, alert_mappings)
                    
                    db.session.commit()
                    print(f"Saved analysis to database with ID: {pcap_entry.id}")

                except Exception as db_err:
                    db.session.rollback()
                    print(f"Database error: {str(db_err)}")
                    # Continue anyway, don't fail the request just because DB failed
                # --- DATABASE INTEGRATION END ---
                
                return jsonify({
                    'message': 'Files uploaded and analyzed successfully',
                    'filename': final_filename,
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
        stats = status.get('stats', {})

        return jsonify({
            'is_monitoring': status.get('is_monitoring', False),
            'interface': status.get('interface') or default_interface or "Ethernet",
            'total_packets': stats.get('total_packets', 0),
            'total_alerts': stats.get('alerts_count', 0),
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
        # Ambil statistik nyata dari monitor
        from real_time_alerts import monitor

        stats = getattr(monitor, 'stats', {})
        # Hitung packet rate berdasarkan paket dalam 5 detik terakhir
        now = datetime.now()
        recent_packets = list(getattr(monitor, 'recent_packets', []))
        window_seconds = 5
        recent_count = 0
        top_sources = {}
        for p in recent_packets:
            try:
                ts = datetime.fromisoformat(p.get('timestamp'))
                if (now - ts).total_seconds() <= window_seconds:
                    recent_count += 1
            except:
                continue
            src = p.get('src_ip')
            if src:
                top_sources[src] = top_sources.get(src, 0) + 1

        protocols = {
            'TCP': stats.get('tcp_packets', 0),
            'UDP': stats.get('udp_packets', 0),
            'ICMP': stats.get('icmp_packets', 0),
            'Other': max(stats.get('total_packets', 0) - stats.get('tcp_packets', 0) - stats.get('udp_packets', 0) - stats.get('icmp_packets', 0), 0)
        }

        return jsonify({
            'protocols': protocols,
            'packet_rate': int(recent_count / window_seconds) if window_seconds > 0 else 0,
            'top_sources': top_sources
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
        # Return recent alerts dari monitor
        from real_time_alerts import monitor
        alerts = monitor.get_alerts() if hasattr(monitor, 'get_alerts') else []
        return jsonify({
            'status': 'success',
            'alerts': alerts
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
            'status': 'success',
            'logs': logs,
            'count': len(logs)
        })
    except Exception as e:
        return jsonify({
            'logs': [],
            'count': 0,
            'error': str(e)
        })

# SSE stream untuk live alerts
@app.route('/api/monitoring/alerts/stream')
@require_auth('view')
def monitoring_alerts_stream():
    try:
        from real_time_alerts import monitor

        def event_stream():
            # Kirim keep-alive setiap beberapa detik untuk menjaga koneksi
            while True:
                try:
                    alert = None
                    if hasattr(monitor, 'alert_queue') and monitor.alert_queue:
                        try:
                            alert = monitor.alert_queue.get(timeout=10)
                        except Exception:
                            alert = None
                    if alert:
                        yield f"data: {json.dumps(alert)}\n\n"
                    else:
                        # keep-alive comment
                        yield ": keep-alive\n\n"
                except GeneratorExit:
                    break
                except Exception:
                    # Hindari memutus stream karena error sementara
                    yield ": keep-alive\n\n"

        headers = {
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
        return Response(event_stream(), mimetype='text/event-stream', headers=headers)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Endpoint history berbasis DB: logs
@app.route('/api/history/logs', methods=['GET'])
@require_auth('view')
def history_logs():
    try:
        from db import DB_ENABLED, get_session, PacketLog
        if not DB_ENABLED:
            return jsonify({'status': 'error', 'message': 'Database not enabled'}), 400
        session_db = get_session()
        q = session_db.query(PacketLog)

        # Filter opsional
        limit = int(request.args.get('limit', '200'))
        src_ip = request.args.get('src_ip')
        protocol = request.args.get('protocol')
        since = request.args.get('since')  # ISO timestamp

        if src_ip:
            q = q.filter(PacketLog.src_ip == src_ip)
        if protocol:
            q = q.filter(PacketLog.protocol == protocol)
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
                q = q.filter(PacketLog.ts >= since_dt)
            except Exception:
                pass

        q = q.order_by(PacketLog.ts.desc()).limit(min(max(limit, 1), 1000))
        rows = q.all()
        logs = [
            {
                'timestamp': r.ts.isoformat(),
                'protocol': r.protocol,
                'src_ip': r.src_ip,
                'src_port': r.src_port or '',
                'dst_ip': r.dst_ip,
                'dst_port': r.dst_port or '',
                'size': r.size,
                'interface': r.interface,
            }
            for r in rows
        ]
        try:
            session_db.close()
        except Exception:
            pass
        return jsonify({'status': 'success', 'count': len(logs), 'logs': logs})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Endpoint history berbasis DB: alerts
@app.route('/api/history/alerts', methods=['GET'])
@require_auth('view')
def history_alerts():
    try:
        from db import DB_ENABLED, get_session, Alert
        if not DB_ENABLED:
            return jsonify({'status': 'error', 'message': 'Database not enabled'}), 400
        session_db = get_session()
        q = session_db.query(Alert)

        limit = int(request.args.get('limit', '200'))
        source_ip = request.args.get('source_ip')
        alert_type = request.args.get('type')
        severity = request.args.get('severity')
        since = request.args.get('since')

        if source_ip:
            q = q.filter(Alert.source_ip == source_ip)
        if alert_type:
            q = q.filter(Alert.type == alert_type)
        if severity:
            q = q.filter(Alert.severity == severity)
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
                q = q.filter(Alert.ts >= since_dt)
            except Exception:
                pass

        q = q.order_by(Alert.ts.desc()).limit(min(max(limit, 1), 1000))
        rows = q.all()
        alerts = [
            {
                'timestamp': r.ts.isoformat(),
                'type': r.type,
                'severity': r.severity,
                'source_ip': r.source_ip,
                'description': r.description,
            }
            for r in rows
        ]
        try:
            session_db.close()
        except Exception:
            pass
        return jsonify({'status': 'success', 'count': len(alerts), 'alerts': alerts})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

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

@app.route('/api/packets', methods=['GET'])
def get_packets():
    try:
        filename = request.args.get('filename')
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 50))
        
        if not filename:
            return jsonify({'error': 'Filename is required'}), 400
            
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
            
        # Read CSV file (assuming file size is manageable as per upload limit)
        df = pd.read_csv(file_path)
        total_records = len(df)
        
        # Calculate pagination
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        
        # Get slice
        data_slice = df.iloc[start_idx:end_idx]
        
        return jsonify({
            'data': data_slice.fillna('Unknown').to_dict(orient='records'),
            'total': total_records,
            'page': page,
            'limit': limit,
            'pages': (total_records + limit - 1) // limit
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/packets', methods=['GET'])
def export_packets():
    try:
        filename = request.args.get('filename')
        if not filename:
            return jsonify({'error': 'Filename is required'}), 400
            
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
            
        # Read CSV
        df = pd.read_csv(file_path)
        
        # Define Excel filename
        excel_filename = filename.replace('.csv', '.xlsx')
        if not excel_filename.endswith('.xlsx'):
             excel_filename += '.xlsx'
             
        excel_path = os.path.join(app.config['UPLOAD_FOLDER'], excel_filename)
        
        # Remove existing file if it exists to ensure fresh write
        if os.path.exists(excel_path):
            try:
                os.remove(excel_path)
            except Exception:
                pass

        # Save to Excel
        df.to_excel(excel_path, index=False, engine='openpyxl')
        
        return send_file(
            excel_path,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='preprocessing_results.xlsx'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
