from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from firebase_config import firebase  # Import your firebase manager
import hmac
import hashlib
import os
import uuid
import traceback
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
# IMPORTANT: Set a secret key for session management.
# You MUST change this to a long, random string for security.
app.secret_key = 'pvc-pro-a-very-secret-and-random-key-12345'

# --- Environment Variables ---
# You must set this in your Cloud Run service settings
CASHFREE_WEBHOOK_SECRET = os.getenv("CASHFREE_WEBHOOK_SECRET")

# --- Main Routes (Pages) ---

@app.route("/")
def render_homepage():
    """Renders the main homepage."""
    return render_template('index.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            # Use your FirebaseManager to sign in the user
            user = firebase.auth.sign_in_with_email_and_password(email, password)
            
            # Get user profile from Firestore
            user_profile_doc = firebase.db.collection('users').document(user['localId']).get()
            if user_profile_doc.exists:
                user_data = user_profile_doc.to_dict()
                session['user'] = user_data  # Store user data in the session
                return redirect(url_for('dashboard'))
            else:
                return render_template('login.html', error="User profile not found.")
                
        except Exception as e:
            return render_template('login.html', error="Invalid email or password.")
            
    return render_template('login.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    """Handles new user registration."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        mobile = request.form['mobile']
        
        try:
            # Use Firebase Admin to create the auth user
            user = firebase_admin.auth.create_user(email=email, password=password, display_name=name)
            
            # Create the user profile in Firestore
            user_data = {
                "uid": user.uid,
                "email": email,
                "name": name,
                "mobile": mobile,
                "is_activated": False,
                "credits": 0,
                "status": "Registered",
                "registered_on": firestore.SERVER_TIMESTAMP
            }
            firebase.db.collection('users').document(user.uid).set(user_data)
            
            # Redirect to login page after successful registration
            return redirect(url_for('login'))
            
        except Exception as e:
            return render_template('register.html', error=f"Registration failed: {e}")

    return render_template('register.html')

@app.route("/dashboard")
def dashboard():
    """Displays the user's dashboard if they are logged in."""
    if 'user' in session:
        # Refresh user data from Firestore to get the latest info
        user_id = session['user']['uid']
        user_profile_doc = firebase.db.collection('users').document(user_id).get()
        if user_profile_doc.exists:
            session['user'] = user_profile_doc.to_dict()
            return render_template('dashboard.html', user=session['user'])
    
    # If user is not in session, redirect to login
    return redirect(url_for('login'))

@app.route("/logout")
def logout():
    """Logs the user out."""
    session.pop('user', None)
    return redirect(url_for('render_homepage'))

# --- API and Webhook Routes ---

@app.route("/create_order", methods=["POST"])
def create_order():
    """API endpoint to create a payment order with Cashfree."""
    if 'user' not in session:
        return jsonify({"error": "User not logged in"}), 401

    data = request.json
    user_id = session['user']['uid']
    
    order_id = "ORDER_" + str(uuid.uuid4()).replace("-", "")[:12]
    
    order_data = {
        "order_id": order_id,
        "order_amount": data.get("order_amount"),
        "order_currency": "INR",
        "order_note": data.get("order_note"),
        "customer_details": {
            "customer_id": user_id,
            "customer_email": session['user']['email'],
            "customer_phone": session['user']['mobile'],
            "customer_name": session['user']['name']
        },
        "order_meta": {
             "notify_url": url_for('cashfree_webhook', _external=True)
        },
        "order_tags": {
            "internal_user_id": user_id
        }
    }

    try:
        response = requests.post(firebase.CASHFREE_URL, headers=firebase.HEADERS, json=order_data)
        response.raise_for_status()
        result = response.json()
        return jsonify({"paymentSessionId": result.get("payment_session_id")})
    except Exception as e:
        app.logger.error(f"Error creating order: {e}")
        return jsonify({"error": "Could not create payment order."}), 500

@app.route("/cashfree-webhook", methods=['POST'])
def cashfree_webhook():
    """Handles incoming webhooks from Cashfree."""
    app.logger.info("--- Webhook Received ---")
    try:
        # Log details for debugging
        app.logger.info(f"Headers: {request.headers}")
        raw_body = request.get_data()
        app.logger.info(f"Raw Body: {raw_body}")

        received_signature = request.headers.get('x-webhook-signature')
        timestamp = request.headers.get('x-webhook-timestamp')

        if not received_signature or not timestamp or not CASHFREE_WEBHOOK_SECRET:
            app.logger.error("Webhook missing headers or server-side secret key.")
            return jsonify({"error": "Configuration error"}), 400

        # Verify the signature
        payload = f"{timestamp}{raw_body.decode('utf-8')}"
        computed_signature = hmac.new(key=CASHFREE_WEBHOOK_SECRET.encode('utf-8'), msg=payload.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()

        if not hmac.compare_digest(computed_signature, received_signature):
            app.logger.error("Webhook signature verification failed.")
            return jsonify({"error": "Signature mismatch"}), 400
        
        app.logger.info("Webhook signature verified successfully!")
        
        # Process the data
        webhook_data = request.get_json()
        order_data = webhook_data.get('data', {}).get('order', {})
        payment_status = order_data.get('order_status')
        
        if payment_status == 'PAID':
            user_id = order_data.get('order_tags', {}).get('internal_user_id')
            if user_id:
                order_note = order_data.get('order_note', '')
                if "Annual Subscription" in order_note:
                    keys_query = firebase.db.collection('activation_keys').where('status', '==', 'UNUSED').limit(1).get()
                    if keys_query:
                        key_doc = keys_query[0]
                        firebase.activate_user(user_id, key_doc.id)
                elif "File Credits" in order_note:
                    amount = float(order_data.get('order_amount', 0))
                    credits_to_add = int(amount)
                    firebase.add_user_credits(user_id, credits_to_add)
        
        return jsonify({"status": "ok"}), 200

    except Exception as e:
        app.logger.error("--- An error occurred in the webhook handler ---")
        app.logger.error(traceback.format_exc())
        return jsonify({"error": "Webhook processing error"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
