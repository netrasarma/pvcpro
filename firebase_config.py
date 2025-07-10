"""
Firebase Configuration and Setup Instructions

Follow these steps to set up your Firebase project:

1. Go to Firebase Console (https://console.firebase.google.com/)
2. Click 'Create a project' or 'Add project'
3. Enter project name (e.g., 'pvc-maker')
4. Enable/disable Google Analytics as preferred
5. Click 'Create project'

After project creation:

6. In Project Overview, click the web icon '</>' to add a web app
7. Register app with a nickname (e.g., 'pvc-maker-web')
8. Copy the firebaseConfig object provided

9. For Admin SDK:
   - Go to Project Settings > Service Accounts
   - Click 'Generate New Private Key'
   - Save the JSON file securely
   - Rename it to 'firebase-adminsdk.json' and place it in this directory

10. Enable Authentication:
    - Go to Authentication > Sign-in method
    - Enable Email/Password provider

11. Set up Firestore Database:
    - Go to Firestore Database
    - Click 'Create database'
    - Start in production mode
    - Choose database location closest to your users

After completing these steps:
1. Replace the FIREBASE_CONFIG below with your web app configuration
2. Ensure firebase-adminsdk.json is in this directory
3. Run 'pip install -r requirements.txt' to install dependencies
"""

# Firebase web app configuration
FIREBASE_CONFIG = {
    "apiKey": "AIzaSyBC7_ZtkquDPObGvmmHYDOCuzfSXANCBvY",
    "authDomain": "pvc-maker.firebaseapp.com",
    "databaseURL": "https://pvc-maker-default-rtdb.firebaseio.com",
    "projectId": "pvc-maker",
    "storageBucket": "pvc-maker.firebasestorage.app",
    "messagingSenderId": "818295298960",
    "appId": "1:818295298960:web:ea07cca1c740bf8988f115"
}

import firebase_admin
from firebase_admin import credentials, firestore, auth
import pyrebase
import hashlib
import uuid
import datetime
import platform
import psutil
import os

class FirebaseManager:
    def __init__(self):
        # Initialize Firebase Admin SDK
        try:
            cred = credentials.Certificate("firebase-adminsdk.json")
            firebase_admin.initialize_app(cred)
        except Exception as e:
            print(f"Error initializing Firebase Admin SDK: {e}")
            print("Please ensure firebase-adminsdk.json is present in the directory")
            return

        # Initialize Pyrebase for client-side operations
        try:
            self.pb = pyrebase.initialize_app(FIREBASE_CONFIG)
            self.auth = self.pb.auth()
            self.db = firestore.client()
            
            # Initialize collections
            self.users_collection = self.db.collection('users')
            self.devices_collection = self.db.collection('devices')
            self.sessions_collection = self.db.collection('sessions')
            self.activation_keys_collection = self.db.collection('activation_keys')
            self.security_logs_collection = self.db.collection('security_logs')
            self.admin_actions_collection = self.db.collection('admin_actions')
            
            # Security settings
            self.max_devices_per_user = 2
            self.max_login_attempts = 5
            self.session_timeout_hours = 24
            self.file_integrity_hashes = {}
            
            # Initialize file integrity monitoring
            self._initialize_file_integrity()
            
        except Exception as e:
            print(f"Error initializing Pyrebase: {e}")
            print("Please check your Firebase configuration")
            return
            
    def _initialize_file_integrity(self):
        """Initialize file integrity monitoring for critical files"""
        critical_files = [
            'main_with_firebase.py',
            'firebase_config.py',
            'requirements.txt'
        ]
        
        for file_path in critical_files:
            if os.path.exists(file_path):
                self.file_integrity_hashes[file_path] = self._calculate_file_hash(file_path)
                
    def _calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of a file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return None
            
    def _get_device_fingerprint(self):
        """Generate unique device fingerprint"""
        try:
            # Collect system information
            system_info = {
                'platform': platform.platform(),
                'processor': platform.processor(),
                'machine': platform.machine(),
                'node': platform.node(),
                'system': platform.system(),
                'release': platform.release()
            }
            
            # Create fingerprint from system info
            fingerprint_string = ''.join(str(v) for v in system_info.values())
            return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]
        except Exception:
            # Fallback to UUID if system info fails
            return str(uuid.uuid4())[:16]
            
    def _log_security_event(self, event_type, user_id=None, details=None):
        """Log security events for monitoring"""
        try:
            log_entry = {
                'event_type': event_type,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'user_id': user_id,
                'details': details or {},
                'device_fingerprint': self._get_device_fingerprint(),
                'ip_address': self._get_client_ip()
            }
            self.security_logs_collection.add(log_entry)
        except Exception as e:
            print(f"Error logging security event: {e}")
            
    def _get_client_ip(self):
        """Get client IP address (placeholder for actual implementation)"""
        # In a real application, this would get the actual client IP
        return "127.0.0.1"
        
    def _check_login_attempts(self, email):
        """Check if user has exceeded login attempts"""
        try:
            # Get recent failed login attempts (last hour)
            one_hour_ago = datetime.datetime.now() - datetime.timedelta(hours=1)
            
            failed_attempts = self.security_logs_collection.where(
                'event_type', '==', 'failed_login'
            ).where(
                'details.email', '==', email
            ).where(
                'timestamp', '>=', one_hour_ago
            ).get()
            
            return len(failed_attempts) >= self.max_login_attempts
        except Exception:
            return False

    def create_user(self, email, password, user_data):
        """Create a new user with Firebase Authentication and Firestore profile"""
        try:
            # Create auth user
            user = auth.create_user(
                email=email,
                password=password
            )
            
            # Create user profile in Firestore
            user_ref = self.db.collection('users').document(user.uid)
            user_data['uid'] = user.uid
            user_data['email'] = email
            user_data['is_activated'] = False
            user_data['status'] = 'Registered'
            user_ref.set(user_data)
            
            return True, user.uid
        except Exception as e:
            return False, str(e)

    def sign_in(self, email, password, device_id=None):
        """Sign in user with email, password and enhanced security checks"""
        try:
            # Generate device ID if not provided
            if not device_id:
                device_id = self._get_device_fingerprint()
            
            # Check login attempts before authentication
            if self._check_login_attempts(email):
                self._log_security_event('login_blocked', details={'email': email, 'reason': 'too_many_attempts'})
                return False, "Too many failed login attempts. Please try again later."
            
            # Verify file integrity before login
            if not self._verify_system_integrity():
                self._log_security_event('integrity_violation', details={'email': email})
                return False, "System integrity check failed. Please contact administrator."
            
            # Authenticate the user
            try:
                user = self.auth.sign_in_with_email_and_password(email, password)
                uid = user['localId']
            except Exception as auth_error:
                # Log failed login attempt
                self._log_security_event('failed_login', details={'email': email, 'error': str(auth_error)})
                return False, "Invalid email or password"
            
            # Check if user is locked
            user_doc = self.users_collection.document(uid).get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                if user_data.get('is_locked', False):
                    self._log_security_event('locked_account_access', user_id=uid, details={'email': email})
                    return False, "Account is locked. Please contact administrator."
            
            # Check device binding
            device_query = self.devices_collection.where('user_id', '==', uid).where('device_id', '==', device_id).limit(1).get()
            
            if not device_query:
                # First time login from this device
                existing_devices = self.devices_collection.where('user_id', '==', uid).get()
                if len(existing_devices) >= self.max_devices_per_user:
                    self._log_security_event('device_limit_exceeded', user_id=uid, details={'email': email, 'device_id': device_id})
                    return False, f"Maximum device limit ({self.max_devices_per_user}) reached"
                    
                # Register new device
                self.devices_collection.add({
                    'user_id': uid,
                    'device_id': device_id,
                    'device_fingerprint': self._get_device_fingerprint(),
                    'registered_date': firestore.SERVER_TIMESTAMP,
                    'last_login': firestore.SERVER_TIMESTAMP,
                    'is_active': True,
                    'platform_info': {
                        'system': platform.system(),
                        'release': platform.release(),
                        'machine': platform.machine()
                    }
                })
                self._log_security_event('new_device_registered', user_id=uid, details={'device_id': device_id})
            else:
                # Check if device is blocked
                device_data = device_query[0].to_dict()
                if not device_data.get('is_active', True):
                    self._log_security_event('blocked_device_access', user_id=uid, details={'device_id': device_id})
                    return False, "This device has been blocked"
                
                # Update last login
                device_query[0].reference.update({
                    'last_login': firestore.SERVER_TIMESTAMP
                })
            
            # Handle session management
            self._clear_old_sessions(uid)
            session_token = self._create_new_session(uid, device_id)
            
            # Log successful login
            self._log_security_event('successful_login', user_id=uid, details={'email': email, 'device_id': device_id})
            
            user['session_token'] = session_token
            user['device_id'] = device_id
            return True, user
            
        except Exception as e:
            self._log_security_event('login_error', details={'email': email, 'error': str(e)})
            return False, str(e)
            
    def _clear_old_sessions(self, uid):
        """Clear old sessions for user"""
        old_sessions = self.sessions_collection.where('user_id', '==', uid).get()
        for session in old_sessions:
            session.reference.delete()
            
    def _create_new_session(self, uid, device_id):
        """Create a new session"""
        import uuid
        session_token = str(uuid.uuid4())
        self.sessions_collection.add({
            'user_id': uid,
            'device_id': device_id,
            'session_token': session_token,
            'created_at': firestore.SERVER_TIMESTAMP,
            'last_active': firestore.SERVER_TIMESTAMP
        })
        return session_token

    def get_user_profile(self, uid):
        """Get user profile from Firestore with security checks"""
        try:
            doc = self.users_collection.document(uid).get()
            if not doc.exists:
                return False, "User profile not found"
                
            user_data = doc.to_dict()
            
            # Check if user is locked
            if user_data.get('is_locked', False):
                return False, "Account is locked. Please contact administrator."
                
            # Verify subscription expiry using server time
            if user_data.get('expires_on'):
                server_time = self.db.collection('utility').document('server_time').get()
                if server_time.exists:
                    current_time = server_time.to_dict().get('timestamp')
                    expiry = datetime.datetime.strptime(user_data['expires_on'], "%Y-%m-%d")
                    if current_time > expiry:
                        return False, "Subscription expired"
            
            return True, user_data
        except Exception as e:
            return False, str(e)

    def update_user_profile(self, uid, data):
        """Update user profile in Firestore with security checks"""
        try:
            # Don't allow updating sensitive fields
            protected_fields = ['is_admin', 'is_locked', 'activation_key', 'subscription_end']
            for field in protected_fields:
                if field in data:
                    del data[field]
                    
            self.users_collection.document(uid).update(data)
            return True, "Profile updated successfully"
        except Exception as e:
            return False, str(e)
            
    def lock_user(self, uid, reason=""):
        """Lock a user account (Admin only)"""
        try:
            self.users_collection.document(uid).update({
                'is_locked': True,
                'lock_reason': reason,
                'locked_at': firestore.SERVER_TIMESTAMP
            })
            return True, "User account locked"
        except Exception as e:
            return False, str(e)
            
    def unlock_user(self, uid):
        """Unlock a user account (Admin only)"""
        try:
            self.users_collection.document(uid).update({
                'is_locked': False,
                'lock_reason': '',
                'locked_at': None
            })
            return True, "User account unlocked"
        except Exception as e:
            return False, str(e)
            
    def disable_device(self, device_id):
        """Disable a device (Admin only)"""
        try:
            device_docs = self.devices_collection.where('device_id', '==', device_id).get()
            for doc in device_docs:
                doc.reference.update({
                    'is_active': False,
                    'disabled_at': firestore.SERVER_TIMESTAMP
                })
            return True, "Device disabled"
        except Exception as e:
            return False, str(e)
            
    def _verify_system_integrity(self):
        """Verify integrity of critical system files"""
        try:
            for file_path, expected_hash in self.file_integrity_hashes.items():
                if os.path.exists(file_path):
                    current_hash = self._calculate_file_hash(file_path)
                    if current_hash != expected_hash:
                        self._log_security_event('file_integrity_violation', details={'file': file_path})
                        return False
                else:
                    self._log_security_event('file_missing', details={'file': file_path})
                    return False
            return True
        except Exception:
            return False
            
    def verify_file_integrity(self, file_path, expected_hash):
        """Verify file integrity using hash"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            return file_hash == expected_hash
        except Exception:
            return False
            
    def validate_session(self, session_token, user_id):
        """Validate user session token"""
        try:
            session_query = self.sessions_collection.where(
                'session_token', '==', session_token
            ).where(
                'user_id', '==', user_id
            ).limit(1).get()
            
            if not session_query:
                return False, "Invalid session"
                
            session_data = session_query[0].to_dict()
            
            # Check session timeout
            created_at = session_data.get('created_at')
            if created_at:
                session_age = datetime.datetime.now() - created_at
                if session_age.total_seconds() > (self.session_timeout_hours * 3600):
                    # Delete expired session
                    session_query[0].reference.delete()
                    return False, "Session expired"
            
            # Update last active
            session_query[0].reference.update({
                'last_active': firestore.SERVER_TIMESTAMP
            })
            
            return True, "Session valid"
        except Exception as e:
            return False, str(e)
            
    def get_user_devices(self, user_id):
        """Get all devices for a user (Admin only)"""
        try:
            devices = self.devices_collection.where('user_id', '==', user_id).get()
            device_list = []
            for device in devices:
                device_data = device.to_dict()
                device_data['id'] = device.id
                device_list.append(device_data)
            return True, device_list
        except Exception as e:
            return False, str(e)
            
    def get_security_logs(self, limit=100, event_type=None):
        """Get security logs (Admin only)"""
        try:
            query = self.security_logs_collection.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)
            
            if event_type:
                query = query.where('event_type', '==', event_type)
                
            logs = query.get()
            log_list = []
            for log in logs:
                log_data = log.to_dict()
                log_data['id'] = log.id
                log_list.append(log_data)
            return True, log_list
        except Exception as e:
            return False, str(e)
            
    def disable_software_remotely(self, reason=""):
        """Disable software remotely (Master Admin only)"""
        try:
            # Create a global disable flag
            disable_doc = self.db.collection('system_control').document('software_status')
            disable_doc.set({
                'is_disabled': True,
                'disabled_at': firestore.SERVER_TIMESTAMP,
                'reason': reason,
                'disabled_by': 'master_admin'
            })
            
            # Log the action
            self._log_security_event('software_disabled', details={'reason': reason})
            
            return True, "Software disabled remotely"
        except Exception as e:
            return False, str(e)
            
    def enable_software_remotely(self):
        """Enable software remotely (Master Admin only)"""
        try:
            # Remove the global disable flag
            disable_doc = self.db.collection('system_control').document('software_status')
            disable_doc.set({
                'is_disabled': False,
                'enabled_at': firestore.SERVER_TIMESTAMP,
                'enabled_by': 'master_admin'
            })
            
            # Log the action
            self._log_security_event('software_enabled')
            
            return True, "Software enabled remotely"
        except Exception as e:
            return False, str(e)
            
    def check_software_status(self):
        """Check if software is remotely disabled"""
        try:
            status_doc = self.db.collection('system_control').document('software_status').get()
            if status_doc.exists:
                status_data = status_doc.to_dict()
                if status_data.get('is_disabled', False):
                    return False, status_data.get('reason', 'Software disabled by administrator')
            return True, "Software enabled"
        except Exception:
            return True, "Software enabled"  # Default to enabled if check fails
            
    def log_admin_action(self, admin_id, action, target_user=None, details=None):
        """Log admin actions for audit trail"""
        try:
            action_entry = {
                'admin_id': admin_id,
                'action': action,
                'target_user': target_user,
                'details': details or {},
                'timestamp': firestore.SERVER_TIMESTAMP,
                'device_fingerprint': self._get_device_fingerprint()
            }
            self.admin_actions_collection.add(action_entry)
            return True, "Action logged"
        except Exception as e:
            return False, str(e)

    def validate_activation_key(self, key):
        """Validate activation key from Firestore"""
        try:
            key_ref = self.db.collection('activation_keys').document(key)
            key_doc = key_ref.get()
            
            if not key_doc.exists:
                return False, "Invalid activation key"
                
            key_data = key_doc.to_dict()
            if key_data.get('status') == 'USED':
                return False, "Key already used"
                
            return True, key_data
        except Exception as e:
            return False, str(e)

    def activate_user(self, uid, key):
        """Activate user subscription with key"""
        try:
            # Update key status
            key_ref = self.db.collection('activation_keys').document(key)
            key_ref.update({
                'status': 'USED',
                'used_by': uid,
                'used_date': firestore.SERVER_TIMESTAMP
            })
            
            # Update user status
            import datetime
            now = datetime.datetime.now()
            expiry = now + datetime.timedelta(days=365)
            
            user_ref = self.db.collection('users').document(uid)
            user_ref.update({
                'is_activated': True,
                'status': 'Active',
                'activation_key': key,
                'activation_date': now,
                'subscription_start': now,
                'subscription_end': expiry,
                'expires_on': expiry.strftime("%Y-%m-%d")
            })
            
            return True, "User activated successfully"
        except Exception as e:
            return False, str(e)

    # ==================== CREDIT MANAGEMENT SYSTEM ====================
    
    def create_payment_request(self, uid, credits, amount, payment_method='UPI'):
        """Create a payment request for credit purchase"""
        try:
            import uuid
            payment_id = f"PVC{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}{str(uuid.uuid4())[:4].upper()}"
            
            payment_data = {
                'payment_id': payment_id,
                'user_id': uid,
                'credits': int(credits),
                'amount': float(amount),
                'payment_method': payment_method,
                'status': 'PENDING',
                'created_at': firestore.SERVER_TIMESTAMP,
                'expires_at': datetime.datetime.now() + datetime.timedelta(hours=1),  # 1 hour expiry
                'upi_id': 'officialnetrasarma@paytm',  # Your UPI ID
                'merchant_name': 'PDF Cropper Pro',
                'transaction_note': f'Credit Purchase - {credits} Credits'
            }
            
            # Store payment request
            payment_ref = self.db.collection('payment_requests').document(payment_id)
            payment_ref.set(payment_data)
            
            # Log payment request
            self._log_security_event('payment_request_created', user_id=uid, details={
                'payment_id': payment_id,
                'credits': credits,
                'amount': amount
            })
            
            return True, payment_data
        except Exception as e:
            return False, str(e)
    
    def verify_payment_status(self, payment_id):
        """Verify payment status (to be integrated with payment gateway webhook)"""
        try:
            payment_ref = self.db.collection('payment_requests').document(payment_id)
            payment_doc = payment_ref.get()
            
            if not payment_doc.exists:
                return False, "Payment request not found"
            
            payment_data = payment_doc.to_dict()
            
            # Check if payment has expired
            if payment_data.get('expires_at') and payment_data['expires_at'] < datetime.datetime.now():
                payment_ref.update({
                    'status': 'EXPIRED',
                    'updated_at': firestore.SERVER_TIMESTAMP
                })
                return False, "Payment request expired"
            
            return True, payment_data
        except Exception as e:
            return False, str(e)
    
    def confirm_payment(self, payment_id, transaction_id=None, payment_gateway_response=None):
        """Confirm payment and add credits to user account"""
        try:
            payment_ref = self.db.collection('payment_requests').document(payment_id)
            payment_doc = payment_ref.get()
            
            if not payment_doc.exists:
                return False, "Payment request not found"
            
            payment_data = payment_doc.to_dict()
            
            if payment_data.get('status') != 'PENDING':
                return False, f"Payment already {payment_data.get('status').lower()}"
            
            # Calculate bonus credits
            credits = payment_data['credits']
            bonus_credits = 0
            if credits >= 1000:
                bonus_credits = 200
            elif credits >= 500:
                bonus_credits = 75
            elif credits >= 250:
                bonus_credits = 25
            
            total_credits = credits + bonus_credits
            
            # Update payment status
            payment_ref.update({
                'status': 'COMPLETED',
                'transaction_id': transaction_id,
                'payment_gateway_response': payment_gateway_response,
                'bonus_credits': bonus_credits,
                'total_credits': total_credits,
                'completed_at': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
            
            # Add credits to user account
            user_id = payment_data['user_id']
            success, result = self.add_user_credits(user_id, total_credits)
            
            if not success:
                # Rollback payment status if credit addition fails
                payment_ref.update({
                    'status': 'FAILED',
                    'error': result,
                    'updated_at': firestore.SERVER_TIMESTAMP
                })
                return False, f"Failed to add credits: {result}"
            
            # Log successful payment
            self._log_security_event('payment_completed', user_id=user_id, details={
                'payment_id': payment_id,
                'credits': credits,
                'bonus_credits': bonus_credits,
                'total_credits': total_credits,
                'amount': payment_data['amount'],
                'transaction_id': transaction_id
            })
            
            return True, {
                'credits_added': total_credits,
                'bonus_credits': bonus_credits,
                'new_balance': result
            }
        except Exception as e:
            return False, str(e)
    
    def add_user_credits(self, uid, credits):
        """Add credits to user account"""
        try:
            user_ref = self.db.collection('users').document(uid)
            user_doc = user_ref.get()
            
            if not user_doc.exists:
                return False, "User not found"
            
            user_data = user_doc.to_dict()
            current_credits = user_data.get('credits', 0)
            new_balance = current_credits + credits
            
            # Update user credits
            user_ref.update({
                'credits': new_balance,
                'last_credit_update': firestore.SERVER_TIMESTAMP
            })
            
            # Log credit transaction
            self.db.collection('credit_transactions').add({
                'user_id': uid,
                'type': 'CREDIT',
                'amount': credits,
                'balance_before': current_credits,
                'balance_after': new_balance,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'description': f'Credits added: {credits}'
            })
            
            return True, new_balance
        except Exception as e:
            return False, str(e)
    
    def deduct_user_credit(self, uid, credits=1):
        """Deduct credits from user account"""
        try:
            user_ref = self.db.collection('users').document(uid)
            user_doc = user_ref.get()
            
            if not user_doc.exists:
                return False, "User not found"
            
            user_data = user_doc.to_dict()
            current_credits = user_data.get('credits', 0)
            
            if current_credits < credits:
                return False, "Insufficient credits"
            
            new_balance = current_credits - credits
            
            # Update user credits
            user_ref.update({
                'credits': new_balance,
                'last_credit_update': firestore.SERVER_TIMESTAMP
            })
            
            # Log credit transaction
            self.db.collection('credit_transactions').add({
                'user_id': uid,
                'type': 'DEBIT',
                'amount': credits,
                'balance_before': current_credits,
                'balance_after': new_balance,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'description': f'Credits deducted for export: {credits}'
            })
            
            return True, new_balance
        except Exception as e:
            return False, str(e)
    
    def get_user_credit_history(self, uid, limit=50):
        """Get user's credit transaction history"""
        try:
            transactions = self.db.collection('credit_transactions')\
                .where('user_id', '==', uid)\
                .order_by('timestamp', direction=firestore.Query.DESCENDING)\
                .limit(limit)\
                .get()
            
            transaction_list = []
            for transaction in transactions:
                transaction_data = transaction.to_dict()
                transaction_data['id'] = transaction.id
                transaction_list.append(transaction_data)
            
            return True, transaction_list
        except Exception as e:
            return False, str(e)
    
    def get_payment_history(self, uid=None, limit=50):
        """Get payment history (admin can see all, users see their own)"""
        try:
            query = self.db.collection('payment_requests')\
                .order_by('created_at', direction=firestore.Query.DESCENDING)\
                .limit(limit)
            
            if uid:
                query = query.where('user_id', '==', uid)
            
            payments = query.get()
            payment_list = []
            for payment in payments:
                payment_data = payment.to_dict()
                payment_data['id'] = payment.id
                payment_list.append(payment_data)
            
            return True, payment_list
        except Exception as e:
            return False, str(e)
    
    def cancel_payment_request(self, payment_id, reason="User cancelled"):
        """Cancel a pending payment request"""
        try:
            payment_ref = self.db.collection('payment_requests').document(payment_id)
            payment_doc = payment_ref.get()
            
            if not payment_doc.exists:
                return False, "Payment request not found"
            
            payment_data = payment_doc.to_dict()
            
            if payment_data.get('status') != 'PENDING':
                return False, f"Cannot cancel payment with status: {payment_data.get('status')}"
            
            # Update payment status
            payment_ref.update({
                'status': 'CANCELLED',
                'cancellation_reason': reason,
                'cancelled_at': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
            
            # Log cancellation
            self._log_security_event('payment_cancelled', user_id=payment_data['user_id'], details={
                'payment_id': payment_id,
                'reason': reason
            })
            
            return True, "Payment request cancelled"
        except Exception as e:
            return False, str(e)
    
    def get_pending_payments(self, uid=None):
        """Get pending payment requests"""
        try:
            query = self.db.collection('payment_requests')\
                .where('status', '==', 'PENDING')\
                .order_by('created_at', direction=firestore.Query.DESCENDING)
            
            if uid:
                query = query.where('user_id', '==', uid)
            
            payments = query.get()
            payment_list = []
            for payment in payments:
                payment_data = payment.to_dict()
                payment_data['id'] = payment.id
                
                # Check if payment has expired
                if payment_data.get('expires_at') and payment_data['expires_at'] < datetime.datetime.now():
                    # Mark as expired
                    payment.reference.update({
                        'status': 'EXPIRED',
                        'updated_at': firestore.SERVER_TIMESTAMP
                    })
                else:
                    payment_list.append(payment_data)
            
            return True, payment_list
        except Exception as e:
            return False, str(e)
    
    def admin_add_credits(self, admin_id, target_uid, credits, reason="Admin credit adjustment"):
        """Admin function to manually add credits to user account"""
        try:
            # Log admin action
            self.log_admin_action(admin_id, 'add_credits', target_uid, {
                'credits': credits,
                'reason': reason
            })
            
            # Add credits
            success, result = self.add_user_credits(target_uid, credits)
            
            if success:
                # Log the transaction with admin details
                self.db.collection('credit_transactions').add({
                    'user_id': target_uid,
                    'type': 'ADMIN_CREDIT',
                    'amount': credits,
                    'balance_after': result,
                    'timestamp': firestore.SERVER_TIMESTAMP,
                    'description': f'Admin credit adjustment: {reason}',
                    'admin_id': admin_id
                })
            
            return success, result
        except Exception as e:
            return False, str(e)
    
    def admin_deduct_credits(self, admin_id, target_uid, credits, reason="Admin credit adjustment"):
        """Admin function to manually deduct credits from user account"""
        try:
            # Log admin action
            self.log_admin_action(admin_id, 'deduct_credits', target_uid, {
                'credits': credits,
                'reason': reason
            })
            
            # Deduct credits
            success, result = self.deduct_user_credit(target_uid, credits)
            
            if success:
                # Log the transaction with admin details
                self.db.collection('credit_transactions').add({
                    'user_id': target_uid,
                    'type': 'ADMIN_DEBIT',
                    'amount': credits,
                    'balance_after': result,
                    'timestamp': firestore.SERVER_TIMESTAMP,
                    'description': f'Admin credit deduction: {reason}',
                    'admin_id': admin_id
                })
            
            return success, result
        except Exception as e:
            return False, str(e)

# Initialize Firebase manager
firebase = FirebaseManager()
