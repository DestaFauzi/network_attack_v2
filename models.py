from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class PcapFile(db.Model):
    __tablename__ = 'uploads'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.now)
    file_size = db.Column(db.String(50))
    total_packets = db.Column(db.Integer)
    malicious_packets = db.Column(db.Integer)
    status = db.Column(db.String(50), default='Processed')
    analysis_json = db.Column(db.Text) 
    
    # Relationship with Alerts
    alerts = db.relationship('Alert', backref='pcap_file', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'upload_time': self.upload_time.strftime('%Y-%m-%d %H:%M:%S'),
            'file_size': self.file_size,
            'total_packets': self.total_packets,
            'malicious_packets': self.malicious_packets,
            'status': self.status
        }

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    upload_id = db.Column(db.Integer, db.ForeignKey('uploads.id'), nullable=False)
    
    rule_name = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    timestamp = db.Column(db.String(50)) # Keeping as string to match PCAP timestamp format
    src_ip = db.Column(db.String(50))
    dst_ip = db.Column(db.String(50))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    detection_method = db.Column(db.String(50))

    def to_dict(self):
        return {
            'rule_name': self.rule_name,
            'severity': self.severity,
            'description': self.description,
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'detection_method': self.detection_method
        }
