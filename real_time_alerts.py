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
        self.packet_counts = defaultdict(int)
        self.connection_tracker = defaultdict(set)
        self.recent_packets = deque(maxlen=1000)
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
        
    def start_monitoring(self, interface=INTERFACE):
        """Start real-time packet monitoring"""
        if self.is_monitoring:
            return {"status": "already_running", "interface": interface}
            
        self.is_monitoring = True
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
        try:
            sniff(
                iface=interface,
                prn=self._process_packet,
                stop_filter=lambda x: not self.is_monitoring,
                store=0
            )
        except Exception as e:
            self.logger.error(f"Packet capture error: {str(e)}")
            self.is_monitoring = False
    
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
                    
                elif UDP in packet:
                    packet_info['protocol'] = 'UDP'
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                    self.stats['udp_packets'] += 1
                    
                elif ICMP in packet:
                    packet_info['protocol'] = 'ICMP'
                    self.stats['icmp_packets'] += 1
            
            # Add to recent packets
            self.recent_packets.append(packet_info)
            
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
    
    def _cleanup_old_data(self):
        """Clean up old tracking data"""
        # Reset packet counts
        self.packet_counts.clear()
        self.connection_tracker.clear()
    
    def get_status(self):
        """Get current monitoring status"""
        return {
            'is_monitoring': self.is_monitoring,
            'stats': self.stats.copy(),
            'recent_alerts': self.alerts[-10:] if self.alerts else [],
            'recent_packets': list(self.recent_packets)[-20:] if self.recent_packets else []
        }
    
    def get_alerts(self, limit=50):
        """Get recent alerts"""
        return self.alerts[-limit:] if self.alerts else []
    
    def get_recent_packets(self, limit=100):
        """Get recent network packets/logs"""
        try:
            # Convert deque to list and get last 'limit' items
            packets = list(self.recent_packets)
            if limit:
                packets = packets[-limit:]
            
            # Format for frontend display - keep original field names
            formatted_packets = []
            for packet in packets:
                formatted_packets.append({
                    'timestamp': packet.get('timestamp', ''),
                    'protocol': packet.get('protocol', 'Unknown'),
                    'src_ip': packet.get('src_ip', 'Unknown'),
                    'dst_ip': packet.get('dst_ip', 'Unknown'),
                    'src_port': packet.get('src_port', ''),
                    'dst_port': packet.get('dst_port', ''),
                    'size': packet.get('size', 0),
                    'details': f"{packet.get('protocol', 'Unknown')} packet from {packet.get('src_ip', 'Unknown')} to {packet.get('dst_ip', 'Unknown')}"
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