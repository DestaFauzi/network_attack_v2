import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import session, request, jsonify, redirect, url_for
import logging
import os
import paramiko
import socket
import io
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class LiveMonitoringAuth:
    def __init__(self):
        # Default credentials (should be changed in production)
        self.users = {
            'admin': {
                'password_hash': self._hash_password('admin123'),
                'role': 'admin',
                'permissions': ['view', 'control', 'configure'],
                'ssh_keys': []
            },
            'monitor': {
                'password_hash': self._hash_password('monitor123'),
                'role': 'monitor',
                'permissions': ['view', 'configure'],  # Tambahkan 'configure'
                'ssh_keys': []
            }
        }
        self.active_sessions = {}
        self.failed_attempts = {}
        self.session_timeout = timedelta(hours=2)
        self.ssh_keys_dir = 'ssh_keys'
        
        # Create SSH keys directory
        os.makedirs(self.ssh_keys_dir, exist_ok=True)
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
    
    def generate_ssh_key_pair(self, username, key_name=None):
        """Generate SSH key pair for user"""
        try:
            if username not in self.users:
                return {'success': False, 'error': 'User not found'}
            
            # Generate RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key (OpenSSH format)
            public_ssh = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            )
            
            # Generate key name if not provided
            if not key_name:
                key_name = f"{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Save keys to files
            private_key_path = os.path.join(self.ssh_keys_dir, f"{key_name}_private.pem")
            public_key_path = os.path.join(self.ssh_keys_dir, f"{key_name}_public.pub")
            
            with open(private_key_path, 'wb') as f:
                f.write(private_pem)
            
            with open(public_key_path, 'wb') as f:
                f.write(public_ssh)
            
            # Add public key to user's authorized keys
            key_info = {
                'key_name': key_name,
                'public_key': public_ssh.decode('utf-8'),
                'created_at': datetime.now().isoformat(),
                'fingerprint': self._get_key_fingerprint(public_ssh)
            }
            
            self.users[username]['ssh_keys'].append(key_info)
            
            return {
                'success': True,
                'key_name': key_name,
                'private_key_path': private_key_path,
                'public_key_path': public_key_path,
                'public_key': public_ssh.decode('utf-8'),
                'fingerprint': key_info['fingerprint']
            }
            
        except Exception as e:
            self.logger.error(f"Error generating SSH key: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def authenticate_with_ssh_key(self, username, private_key_content, ip_address):
        """Authenticate user with SSH private key"""
        try:
            if username not in self.users:
                return {'success': False, 'error': 'User not found'}
            
            # Check if IP is blocked
            if self._is_ip_blocked(ip_address):
                return {'success': False, 'error': 'IP address is temporarily blocked'}
            
            # Load private key
            try:
                private_key = serialization.load_pem_private_key(
                    private_key_content.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
                
                # Get public key from private key
                public_key = private_key.public_key()
                public_ssh = public_key.public_bytes(
                    encoding=serialization.Encoding.OpenSSH,
                    format=serialization.PublicFormat.OpenSSH
                )
                
                # Check if this public key is authorized for the user
                user_keys = self.users[username]['ssh_keys']
                key_found = False
                
                for key_info in user_keys:
                    if key_info['public_key'] == public_ssh.decode('utf-8'):
                        key_found = True
                        break
                
                if not key_found:
                    self._record_failed_attempt(ip_address)
                    return {'success': False, 'error': 'SSH key not authorized'}
                
                # Create session
                session_id = secrets.token_urlsafe(32)
                self.active_sessions[session_id] = {
                    'username': username,
                    'role': self.users[username]['role'],
                    'permissions': self.users[username]['permissions'],
                    'login_time': datetime.now(),
                    'ip_address': ip_address,
                    'auth_method': 'ssh_key'
                }
                
                return {
                    'success': True,
                    'session_id': session_id,
                    'username': username,
                    'role': self.users[username]['role'],
                    'permissions': self.users[username]['permissions']
                }
                
            except Exception as e:
                self._record_failed_attempt(ip_address)
                return {'success': False, 'error': 'Invalid SSH key format'}
                
        except Exception as e:
            self.logger.error(f"SSH key authentication error: {str(e)}")
            return {'success': False, 'error': 'Authentication failed'}
    
    def _get_key_fingerprint(self, public_key_bytes):
        """Generate SSH key fingerprint"""
        import base64
        import hashlib
        
        # Remove the ssh-rsa prefix and decode
        key_parts = public_key_bytes.decode('utf-8').split()
        if len(key_parts) >= 2:
            key_data = base64.b64decode(key_parts[1])
            fingerprint = hashlib.md5(key_data).hexdigest()
            return ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        return 'unknown'
    
    def get_user_ssh_keys(self, username):
        """Get all SSH keys for a user"""
        if username in self.users:
            return self.users[username]['ssh_keys']
        return []
    
    def revoke_ssh_key(self, username, key_name):
        """Revoke an SSH key for a user"""
        try:
            if username not in self.users:
                return {'success': False, 'error': 'User not found'}
            
            user_keys = self.users[username]['ssh_keys']
            key_to_remove = None
            
            for i, key_info in enumerate(user_keys):
                if key_info['key_name'] == key_name:
                    key_to_remove = i
                    break
            
            if key_to_remove is not None:
                removed_key = user_keys.pop(key_to_remove)
                
                # Remove key files
                private_key_path = os.path.join(self.ssh_keys_dir, f"{key_name}_private.pem")
                public_key_path = os.path.join(self.ssh_keys_dir, f"{key_name}_public.pub")
                
                try:
                    if os.path.exists(private_key_path):
                        os.remove(private_key_path)
                    if os.path.exists(public_key_path):
                        os.remove(public_key_path)
                except:
                    pass
                
                return {'success': True, 'message': f'SSH key {key_name} revoked'}
            else:
                return {'success': False, 'error': 'SSH key not found'}
                
        except Exception as e:
            self.logger.error(f"Error revoking SSH key: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _hash_password(self, password):
        """Hash password using PBKDF2-HMAC-SHA256"""
        salt = b'static_salt_for_demo'  # In production, use random salt per user
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    
    def _verify_password(self, password, password_hash):
        """Verify password against hash"""
        return self._hash_password(password) == password_hash
    
    def authenticate_remote_server(self, username, password, server_ip, auth_method='password'):
        """Authenticate against remote server via SSH"""
        try:
            # Create SSH client
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Test connection with timeout
            ssh_client.connect(
                hostname=server_ip,
                username=username,
                password=password,
                timeout=100000,
                auth_timeout=100000
            )
            
            # Test if we can execute a simple command
            stdin, stdout, stderr = ssh_client.exec_command('whoami')
            result = stdout.read().decode().strip()
            
            ssh_client.close()
            
            if result == username:
                # Create session for remote server access
                session_id = secrets.token_urlsafe(32)
                session_data = {
                    'username': username,
                    'server_ip': server_ip,
                    'role': 'remote_monitor',
                    'permissions': ['view', 'control', 'configure'],  # Tambahkan 'configure'
                    'login_time': datetime.now(),
                    'last_activity': datetime.now(),
                    'auth_method': auth_method,
                    'is_remote': True,
                    'ip_address': request.remote_addr if request else 'unknown'
                }
                
                self.active_sessions[session_id] = session_data
                
                self.logger.info(f"Remote authentication successful: {username}@{server_ip}")
                
                return {
                    'success': True,
                    'session_id': session_id,
                    'username': username,
                    'role': 'remote_monitor',
                    'server_ip': server_ip,
                    'message': f'Connected to {server_ip} as {username}'
                }
            else:
                return {
                    'success': False,
                    'error': 'Authentication verification failed'
                }
                
        except paramiko.AuthenticationException:
            self.logger.warning(f"Authentication failed for {username}@{server_ip}")
            return {
                'success': False,
                'error': 'Invalid username or password for remote server'
            }
        except paramiko.SSHException as e:
            self.logger.error(f"SSH connection error to {server_ip}: {str(e)}")
            return {
                'success': False,
                'error': f'SSH connection failed: {str(e)}'
            }
        except socket.timeout:
            return {
                'success': False,
                'error': 'Connection timeout - server may be unreachable'
            }
        except Exception as e:
            self.logger.error(f"Remote authentication error: {str(e)}")
            return {
                'success': False,
                'error': f'Connection failed: {str(e)}'
            }

    def authenticate(self, username, password, ip_address, server_ip=None):
        """Authenticate user with username and password"""
        print(f"DEBUG: Authenticating {username} from {ip_address}, server_ip: {server_ip}")
        
        # Check if IP is blocked
        if self._is_ip_blocked(ip_address):
            return {
                'success': False,
                'error': 'IP address temporarily blocked due to failed attempts'
            }
        
        # If server_ip is provided and not localhost, try remote authentication
        if server_ip and server_ip not in ['127.0.0.1', 'localhost']:
            print(f"DEBUG: Attempting remote authentication to {server_ip}")
            result = self.authenticate_remote_server(username, password, server_ip)
            print(f"DEBUG: Remote auth result: {result}")
            return result
        
        # Local authentication
        if username not in self.users:
            self._record_failed_attempt(ip_address)
            return {'success': False, 'error': 'Invalid username or password'}
        
        user = self.users[username]
        if not self._verify_password(password, user['password_hash']):
            self._record_failed_attempt(ip_address)
            return {'success': False, 'error': 'Invalid username or password'}
        
        # Create session
        session_id = secrets.token_urlsafe(32)
        session_data = {
            'username': username,
            'role': user['role'],
            'permissions': user['permissions'],
            'login_time': datetime.now(),
            'last_activity': datetime.now(),
            'ip_address': ip_address,
            'auth_method': 'password',
            'is_remote': False
        }
        
        self.active_sessions[session_id] = session_data
        print(f"DEBUG: Created session {session_id} for user {username}")
        print(f"DEBUG: Active sessions after creation: {list(self.active_sessions.keys())}")
        
        self.logger.info(f"User {username} authenticated successfully from {ip_address}")
        
        return {
            'success': True,
            'session_id': session_id,
            'username': username,
            'role': user['role']
        }
    
    def validate_session(self, session_id):
        """Validate active session"""
        print(f"DEBUG: Validating session {session_id}")
        print(f"DEBUG: Active sessions: {list(self.active_sessions.keys())}")
        
        if session_id not in self.active_sessions:
            print(f"DEBUG: Session {session_id} not found in active sessions")
            return None
        
        session_data = self.active_sessions[session_id]
        print(f"DEBUG: Session data: {session_data}")
        
        # Check session timeout
        time_diff = datetime.now() - session_data['last_activity']
        print(f"DEBUG: Time since last activity: {time_diff}, Timeout: {self.session_timeout}")
        
        if time_diff > self.session_timeout:
            print(f"DEBUG: Session expired, deleting session {session_id}")
            del self.active_sessions[session_id]
            return None
        
        # Update last activity
        session_data['last_activity'] = datetime.now()
        print(f"DEBUG: Session validated successfully")
        return session_data
    
    def logout(self, session_id):
        """Logout user session"""
        if session_id in self.active_sessions:
            username = self.active_sessions[session_id]['username']
            del self.active_sessions[session_id]
            self.logger.info(f"User {username} logged out")
            return True
        return False
    
    def _record_failed_attempt(self, ip_address):
        """Record failed login attempt"""
        now = datetime.now()
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = []
        
        self.failed_attempts[ip_address].append(now)
        
        # Clean old attempts (older than 1 hour)
        self.failed_attempts[ip_address] = [
            attempt for attempt in self.failed_attempts[ip_address]
            if now - attempt < timedelta(hours=1)
        ]
    
    def _is_ip_blocked(self, ip_address):
        """Check if IP is blocked due to failed attempts"""
        if ip_address not in self.failed_attempts:
            return False
        
        recent_attempts = len(self.failed_attempts[ip_address])
        return recent_attempts >= 5  # Block after 5 failed attempts
    
    def has_permission(self, session_id, permission):
        """Check if session has required permission"""
        session_data = self.validate_session(session_id)
        if not session_data:
            return False
        
        return permission in session_data.get('permissions', [])
    
    def get_active_sessions(self):
        """Get list of active sessions"""
        return [
            {
                'username': data['username'],
                'role': data['role'],
                'login_time': data['login_time'].isoformat(),
                'last_activity': data['last_activity'].isoformat(),
                'ip_address': data['ip_address']
            }
            for data in self.active_sessions.values()
        ]

# Di akhir file, pastikan hanya ada satu instance:
# Global authentication instance
auth_manager = LiveMonitoringAuth()

# Pastikan semua fungsi menggunakan instance yang sama
def require_auth(permission='view'):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            session_id = session.get('session_id')
            
            if not session_id:
                # Check if this is an API request
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Authentication required'}), 401
                else:
                    return redirect(url_for('login'))
            
            # Gunakan instance global yang sama
            session_data = auth_manager.validate_session(session_id)
            if not session_data:
                session.pop('session_id', None)
                # Check if this is an API request
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Session expired'}), 401
                else:
                    return redirect(url_for('login'))
            
            if not auth_manager.has_permission(session_id, permission):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            request.user = session_data
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def require_login(f):
    """Decorator to require login for web pages"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_id = session.get('session_id')
        
        if not session_id or not auth_manager.validate_session(session_id):
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function