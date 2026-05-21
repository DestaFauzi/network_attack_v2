import threading
import time
import json
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict, deque
import logging
from config import *

class RealTimeMonitor:
    def __init__(self):
        self.is_monitoring = False
        self.interface = None
        self.start_time = None
        self.packet_counts = defaultdict(int)
        self.connection_tracker = defaultdict(set)
        # Buffer siklik untuk realtime logs (maks 50 item)
        self.recent_packets = deque(maxlen=50)
        self.alerts = []
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'alerts_count': 0
        }
        
        # Setup logging
        logging.basicConfig(
            filename=LOG_FILE,
            level=getattr(logging, LOG_LEVEL),
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        # Queues untuk integrasi DB dan SSE (non-blocking)
        try:
            from queue import Queue
            self.db_queue = Queue(maxsize=5000)
            self.alert_queue = Queue(maxsize=1000)
        except Exception:
            self.db_queue = None
            self.alert_queue = None
        self._db_writer_started = False
        
    def start_monitoring(self, interface=INTERFACE):
        """Start real-time packet monitoring"""
        if self.is_monitoring:
            return {"status": "already_running", "interface": interface}
            
        self.is_monitoring = True
        self.interface = interface
        self.start_time = datetime.now()
        self.logger.info(f"Starting real-time monitoring on interface: {interface}")
        
        try:
            # Validate interface
            if not interface or interface == "":
                interface = INTERFACE
                
            # Start packet capture in separate thread
            monitor_thread = threading.Thread(
                target=self._capture_packets,
                args=(interface,),
                daemon=True
            )
            monitor_thread.start()
            
            # Start analysis thread
            analysis_thread = threading.Thread(
                target=self._analyze_traffic,
                daemon=True
            )
            analysis_thread.start()

            # Start DB writer thread jika DB aktif
            try:
                from db import init_db, DB_ENABLED
                init_db()
                if DB_ENABLED and not self._db_writer_started and self.db_queue:
                    db_thread = threading.Thread(
                        target=self._db_writer_loop,
                        daemon=True
                    )
                    db_thread.start()
                    self._db_writer_started = True
            except Exception as e:
                self.logger.warning(f"DB writer not started: {e}")
            
            return {"status": "started", "interface": interface}
            
        except PermissionError:
            self.logger.error("Permission denied: Run as administrator for packet capture")
            self.is_monitoring = False
            return {"status": "error", "message": "Permission denied. Please run as administrator."}
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {str(e)}")
            self.is_monitoring = False
            return {"status": "error", "message": f"Failed to start monitoring: {str(e)}"}
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.is_monitoring = False
        self.logger.info("Stopping real-time monitoring")
        return {"status": "stopped"}
    
    def _capture_packets(self, interface):
        """Capture packets using Scapy"""
        # Loop dengan retry agar monitoring tidak berhenti jika terjadi error sementara
        while self.is_monitoring:
            try:
                sniff(
                    iface=interface,
                    prn=self._process_packet,
                    stop_filter=lambda x: not self.is_monitoring,
                    store=0,
                    filter="ip or tcp or udp or icmp"
                )
            except Exception as e:
                self.logger.error(f"Packet capture error: {str(e)}")
                # Tunggu sebentar lalu coba lagi selama is_monitoring masih True
                time.sleep(1)
                continue
    
    def _process_packet(self, packet):
        """Process individual packets"""
        if not self.is_monitoring:
            return
            
        try:
            # Update statistics
            self.stats['total_packets'] += 1
            
            # Extract packet information
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'size': len(packet),
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None
            }
            
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                
                if TCP in packet:
                    packet_info['protocol'] = 'TCP'
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                    self.stats['tcp_packets'] += 1
                    # Track destination ports per source IP for port-scan detection
                    if packet_info['src_ip'] and packet_info['dst_port'] is not None:
                        self.connection_tracker[packet_info['src_ip']].add(packet_info['dst_port'])
                    
                elif UDP in packet:
                    packet_info['protocol'] = 'UDP'
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                    self.stats['udp_packets'] += 1
                    if packet_info['src_ip'] and packet_info['dst_port'] is not None:
                        self.connection_tracker[packet_info['src_ip']].add(packet_info['dst_port'])
                    
                elif ICMP in packet:
                    packet_info['protocol'] = 'ICMP'
                    self.stats['icmp_packets'] += 1
            
            # Add to recent packets
            self.recent_packets.append(packet_info)
            # Push to DB queue (non-blocking)
            try:
                if self.db_queue:
                    self.db_queue.put_nowait({
                        '__kind__': 'packet',
                        'timestamp': packet_info['timestamp'],
                        'protocol': packet_info['protocol'],
                        'src_ip': packet_info['src_ip'],
                        'src_port': packet_info['src_port'],
                        'dst_ip': packet_info['dst_ip'],
                        'dst_port': packet_info['dst_port'],
                        'size': packet_info['size'],
                        'interface': self.interface
                    })
            except Exception:
                pass
            
            # Track for analysis
            if packet_info['src_ip']:
                self.packet_counts[packet_info['src_ip']] += 1
                
        except Exception as e:
            self.logger.error(f"Packet processing error: {str(e)}")
    
    def _analyze_traffic(self):
        """Analyze traffic patterns for threats"""
        while self.is_monitoring:
            try:
                time.sleep(ANALYSIS_INTERVAL)
                self._detect_anomalies()
                self._cleanup_old_data()
                
            except Exception as e:
                self.logger.error(f"Traffic analysis error: {str(e)}")
    
    def _detect_anomalies(self):
        """Detect various network anomalies"""
        current_time = datetime.now()
        
        # Check for high packet rate from single IP
        for ip, count in self.packet_counts.items():
            if count > PACKET_RATE_THRESHOLD:
                alert = {
                    'timestamp': current_time.isoformat(),
                    'type': 'High Packet Rate',
                    'severity': 'HIGH',
                    'source_ip': ip,
                    'description': f'IP {ip} sent {count} packets in analysis window',
                    'count': count
                }
                self._add_alert(alert)
        
        # Check for port scanning
        for ip, ports in self.connection_tracker.items():
            if len(ports) > 50:  # Threshold for port scan detection
                alert = {
                    'timestamp': current_time.isoformat(),
                    'type': 'Port Scan',
                    'severity': 'MEDIUM',
                    'source_ip': ip,
                    'description': f'Potential port scan from {ip} - {len(ports)} ports accessed',
                    'ports_count': len(ports)
                }
                self._add_alert(alert)
    
    def _add_alert(self, alert):
        """Add new alert to the system"""
        self.alerts.append(alert)
        self.stats['alerts_count'] += 1
        self.logger.warning(f"ALERT: {alert['type']} from {alert.get('source_ip', 'Unknown')}")
        
        # Keep only recent alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]

        # Kirim ke alert_queue untuk SSE stream
        try:
            if self.alert_queue:
                self.alert_queue.put_nowait(alert)
        except Exception:
            pass

        # Persist alert ke DB queue
        try:
            if self.db_queue:
                self.db_queue.put_nowait({
                    '__kind__': 'alert',
                    'timestamp': alert.get('timestamp'),
                    'type': alert.get('type'),
                    'severity': alert.get('severity'),
                    'source_ip': alert.get('source_ip'),
                    'description': alert.get('description')
                })
        except Exception:
            pass

        # Opsional: kirim NOTIFY ke Postgres untuk konsumen eksternal
        try:
            from db import pg_notify
            pg_notify('alerts', alert)
        except Exception:
            pass

    def _cleanup_old_data(self):
        """Clean up old tracking data"""
        # Reset packet counts
        self.packet_counts.clear()
        self.connection_tracker.clear()
    
    def get_status(self):
        """Get current monitoring status"""
        uptime_seconds = 0
        start_time_iso = None
        if self.start_time:
            start_time_iso = self.start_time.isoformat()
            if self.is_monitoring:
                uptime_seconds = int((datetime.now() - self.start_time).total_seconds())
        return {
            'is_monitoring': self.is_monitoring,
            'interface': self.interface,
            'start_time': start_time_iso,
            'uptime': uptime_seconds,
            'stats': self.stats.copy(),
            'recent_alerts': self.alerts[-10:] if self.alerts else [],
            'recent_packets': list(self.recent_packets)[-20:] if self.recent_packets else []
        }
    
    def get_alerts(self, limit=50):
        """Get recent alerts"""
        return self.alerts[-limit:] if self.alerts else []
    
    def get_recent_packets(self, limit=50):
        """Get recent network packets/logs"""
        try:
            # Convert deque to list and get last 'limit' items
            packets = list(self.recent_packets)
            if limit:
                packets = packets[-limit:]
            
            # Format for frontend display - keep original field names
            formatted_packets = []
            for packet in packets:
                # Sanitasi nilai None menjadi 'Unknown' untuk tampilan
                timestamp = packet.get('timestamp') or datetime.now().isoformat()
                protocol = packet.get('protocol') or 'Unknown'
                src_ip = packet.get('src_ip') or 'Unknown'
                dst_ip = packet.get('dst_ip') or 'Unknown'
                src_port = packet.get('src_port') if packet.get('src_port') is not None else ''
                dst_port = packet.get('dst_port') if packet.get('dst_port') is not None else ''
                size = packet.get('size', 0)
                formatted_packets.append({
                    'timestamp': timestamp,
                    'protocol': protocol,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'size': size,
                    'details': f"{protocol} packet from {src_ip} to {dst_ip}"
                })
            
            return formatted_packets
            
        except Exception as e:
            self.logger.error(f"Error getting recent packets: {str(e)}")
            return []

# Global monitor instance
monitor = RealTimeMonitor()

def start_live_monitoring(interface=None):
    """Start live monitoring"""
    if interface is None:
        interface = INTERFACE
    return monitor.start_monitoring(interface)

def stop_live_monitoring():
    """Stop live monitoring"""
    return monitor.stop_monitoring()

def get_monitoring_status():
    """Get current monitoring status"""
    return monitor.get_status()

def get_live_alerts():
    """Get live alerts"""
    return monitor.get_alerts()
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    def _db_writer_loop(self):
        """Batch insert packet logs and alerts into DB"""
        try:
            from db import DB_ENABLED, get_session, PacketLog, Alert
            if not DB_ENABLED:
                return
            import time
            batch = []
            last_commit = time.time()
            while True:
                try:
                    item = self.db_queue.get(timeout=0.5)
                    batch.append(item)
                except Exception:
                    pass

                now = time.time()
                if batch and (len(batch) >= 500 or now - last_commit >= 1.0):
                    session = get_session()
                    try:
                        for it in batch:
                            kind = it.get('__kind__')
                            if kind == 'alert':
                                session.add(Alert(
                                    ts=datetime.fromisoformat(it['timestamp']) if isinstance(it['timestamp'], str) else (it['timestamp'] or datetime.utcnow()),
                                    type=it.get('type'),
                                    severity=it.get('severity'),
                                    source_ip=it.get('source_ip'),
                                    description=it.get('description')
                                ))
                            else:
                                session.add(PacketLog(
                                    ts=datetime.fromisoformat(it['timestamp']) if isinstance(it['timestamp'], str) else (it['timestamp'] or datetime.utcnow()),
                                    protocol=it.get('protocol'),
                                    src_ip=it.get('src_ip'),
                                    src_port=it.get('src_port'),
                                    dst_ip=it.get('dst_ip'),
                                    dst_port=it.get('dst_port'),
                                    size=it.get('size'),
                                    interface=it.get('interface')
                                ))
                        session.commit()
                    except Exception as e:
                        try:
                            session.rollback()
                        except Exception:
                            pass
                        self.logger.error(f"DB writer error: {e}")
                    finally:
                        try:
                            session.close()
                        except Exception:
                            pass
                    batch = []
                    last_commit = now
        except Exception as e:
            self.logger.warning(f"DB writer loop exited: {e}")
