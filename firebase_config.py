import firebase_admin
from firebase_admin import credentials, firestore, auth
import pyrebase
import hashlib
import uuid
import datetime

# Firebase web app configuration
FIREBASE_CONFIG = {
    "apiKey": "AIzaSyBC7_ZtkquDPObGvmmHYDOCuzfSXANCBvY",
    "authDomain": "pvc-maker.firebaseapp.com",
    "databaseURL": "https://pvc-maker-default-rtdb.firebaseio.com",
    "projectId": "pvc-maker",
    "storageBucket": "pvc-maker.appspot.com",
    "messagingSenderId": "818295298960",
    "appId": "1:818295298960:web:ea07cca1c740bf8988f115"
}

class FirebaseManager:
    def __init__(self):
        # Initialize Firebase Admin SDK
        try:
            if not firebase_admin._apps:
                cred = credentials.Certificate("firebase-adminsdk.json")
                firebase_admin.initialize_app(cred)
        except Exception as e:
            print(f"Error initializing Firebase Admin SDK: {e}")
            return

        # Initialize Pyrebase for client-side operations
        try:
            self.pb = pyrebase.initialize_app(FIREBASE_CONFIG)
            self.auth = self.pb.auth()
            self.db = firestore.client()
        except Exception as e:
            print(f"Error initializing Pyrebase: {e}")
            return

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
            now = datetime.datetime.now(datetime.timezone.utc)
            expiry = now + datetime.timedelta(days=365)
            
            user_ref = self.db.collection('users').document(uid)
            user_ref.update({
                'is_activated': True,
                'status': 'Active',
                'activation_key': key,
                'activation_date': now,
                'expires_on': expiry.strftime("%Y-%m-%d")
            })
            return True, "User activated successfully"
        except Exception as e:
            return False, str(e)

    def add_user_credits(self, uid, credits):
        """Add credits to user account"""
        try:
            user_ref = self.db.collection('users').document(uid)
            
            @firestore.transactional
            def update_in_transaction(transaction, user_ref_to_update, credits_to_add):
                snapshot = user_ref_to_update.get(transaction=transaction)
                current_credits = snapshot.get('credits') or 0
                new_balance = current_credits + credits_to_add
                transaction.update(user_ref_to_update, {
                    'credits': new_balance,
                    'last_credit_update': firestore.SERVER_TIMESTAMP
                })
                return new_balance

            transaction = self.db.transaction()
            update_in_transaction(transaction, user_ref, credits)

            return True, "Credits added successfully"
        except Exception as e:
            return False, str(e)

# Initialize a single instance of the Firebase manager for the app to use
firebase = FirebaseManager()
