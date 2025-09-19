import socket
import subprocess
import platform
import psutil

# Network monitoring configuration
MONITORING_ENABLED = True

def get_available_interfaces():
    """Get list of available network interfaces using psutil"""
    try:
        interfaces = []
        net_if_stats = psutil.net_if_stats()
        net_if_addrs = psutil.net_if_addrs()
        
        for interface, stats in net_if_stats.items():
            if stats.isup and interface != 'lo' and not interface.startswith('Loopback'):
                try:
                    if interface in net_if_addrs:
                        for addr in net_if_addrs[interface]:
                            if addr.family == socket.AF_INET:  # IPv4
                                interfaces.append({
                                    'name': interface,
                                    'ip': addr.address,
                                    'is_up': stats.isup
                                })
                                break
                except:
                    continue
        
        return interfaces
    except:
        return [{'name': 'any', 'ip': '0.0.0.0', 'is_up': True}]

def get_default_interface():
    """Get default network interface for monitoring"""
    try:
        # For Windows, try to get default interface via route command
        if platform.system() == "Windows":
            try:
                # Coba dapatkan interface aktif dengan psutil
                interfaces = get_available_interfaces()
                if interfaces:
                    # Pilih interface pertama yang aktif
                    for iface in interfaces:
                        if iface['is_up'] and iface['name'] != 'Loopback':
                            return iface['name']
                
                # Fallback ke Ethernet adapter
                result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Connected' in line and 'Ethernet' in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                return parts[-1]  # Nama interface
            except:
                pass
        
        # Fallback: get first active interface
        interfaces = get_available_interfaces()
        if interfaces:
            return interfaces[0]['name']
        
        # Ultimate fallback untuk Windows
        return "Ethernet"  # Nama interface umum di Windows
        
    except:
        return "Ethernet"  # Default fallback

    return "any"

# Network interface to monitor (auto-detected)
INTERFACE = get_default_interface()
AVAILABLE_INTERFACES = get_available_interfaces()

# Packet capture settings
PACKET_COUNT = 0  # 0 means capture indefinitely
TIMEOUT = None  # None means no timeout
PROMISCUOUS_MODE = True

# Logging configuration
LOG_FILE = "network_monitor.log"
LOG_LEVEL = "INFO"

# Alert thresholds
PACKET_RATE_THRESHOLD = 1000  # Packets per second
BANDWIDTH_THRESHOLD = 10000000  # Bytes per second (10MB/s)

# Database settings
DB_HOST = "localhost"
DB_PORT = 3306
DB_NAME = "nids_db"
DB_USER = "nids_user"
DB_PASSWORD = "nids_password"

# Alert notification
ENABLE_EMAIL_ALERTS = False
EMAIL_FROM = "alerts@example.com"
EMAIL_TO = ["admin@example.com"]
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "alerts@example.com"
SMTP_PASSWORD = "your_smtp_password"

# Detection rules
DETECTION_RULES = {
    "syn_flood": {
        "enabled": True,
        "threshold": 100  # SYN packets per second
    },
    "port_scan": {
        "enabled": True,
        "threshold": 50  # Different ports per minute
    },
    "ping_flood": {
        "enabled": True,
        "threshold": 50  # ICMP packets per second
    }
}

# Analysis settings
ANALYSIS_INTERVAL = 60  # Analysis interval in seconds
HISTORY_RETENTION = 7  # Days to keep historical data
