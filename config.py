# Network monitoring configuration
MONITORING_ENABLED = True


# Network interface to monitor
INTERFACE = "eth0"  # Change this to your network interface

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
