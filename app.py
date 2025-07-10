from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from firebase_config import firebase  # Import your firebase manager
import hmac
import hashlib
import os

app = Flask(__name__)
# IMPORTANT: Set a secret key for session management.
# You MUST change this to a long, random string.
app.secret_key = 'your-very-secret-and-random-key'

# --- Environment Variables ---
# You must set these in your Cloud Run service settings
CASHFREE_WEBHOOK_SECRET = os.getenv("CASHFREE_WEBHOOK_SECRET")

# --- Main Routes (Pages) ---

@app.route("/")
def render_homepage():
    return render_template('index.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            # Use your FirebaseManager to sign in the user
            user = firebase.auth.sign_in_with_email_and_password(email, password)
            
            # Get user profile from Firestore
            user_profile = firebase.db.collection('users').document(user['localId']).get()
            if user_profile.exists:
                session['user'] = user_profile.to_dict()
                session['user']['idToken'] = user['idToken'] # Store token for auth
                return redirect(url_for('dashboard'))
            else:
                return render_template('login.html', error="User profile not found.")
                
        except Exception as e:
            return render_template('login.html', error="Invalid email or password.")
            
    return render_template('login.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        mobile = request.form['mobile']
        
        try:
            # Create the user in Firebase Auth
            user = auth.create_user(email=email, password=password, display_name=name)
            
            # Create the user profile in Firestore using your FirebaseManager logic
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
            
            return redirect(url_for('login'))
            
        except Exception as e:
            return render_template('register.html', error=f"Registration failed: {e}")

    return render_template('register.html')

@app.route("/dashboard")
def dashboard():
    if 'user' in session:
        # Refresh user data from Firestore
        user_id = session['user']['uid']
        user_profile_doc = firebase.db.collection('users').document(user_id).get()
        if user_profile_doc.exists:
            session['user'] = user_profile_doc.to_dict()
            return render_template('dashboard.html', user=session['user'])
    
    return redirect(url_for('login'))

@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for('render_homepage'))

# --- API and Webhook Routes ---

@app.route("/create_order", methods=["POST"])
def create_order():
    if 'user' not in session:
        return jsonify({"error": "User not logged in"}), 401

    data = request.json
    user_id = session['user']['uid']

    # Your existing order creation logic...
    order_id = "ORDER_" + str(uuid.uuid4()).replace("-", "")[:12]
    
    # Add user_id and order_id to the metadata for the webhook
    order_meta = {
        "return_url": data.get("return_url", url_for('dashboard', _external=True)),
        "notify_url": url_for('cashfree_webhook', _external=True),
        "payment_methods": "cc,dc,nb,upi,paypal"
    }
    
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
        "order_meta": order_meta,
        # This tag is used to pass our internal user_id to the webhook
        "order_tags": {
            "internal_user_id": user_id
        }
    }

    try:
        response = requests.post(CASHFREE_URL, headers=HEADERS, json=order_data)
        response.raise_for_status()
        result = response.json()
        return jsonify({"paymentSessionId": result.get("payment_session_id")})
    except Exception as e:
        app.logger.error(f"Error creating order: {e}")
        return jsonify({"error": "Could not create payment order."}), 500

@app.route("/cashfree_webhook", methods=['POST'])
def cashfree_webhook():
    webhook_data = request.json
    received_signature = request.headers.get('x-webhook-signature')
    timestamp = request.headers.get('x-webhook-timestamp')
    
    if not received_signature or not timestamp:
        return jsonify({"error": "Missing headers"}), 400

    # 1. Verify the webhook signature for security
    payload = f"{timestamp}{request.get_data(as_text=True)}"
    computed_signature = hmac.new(
        key=CASHFREE_WEBHOOK_SECRET.encode('utf-8'),
        msg=payload.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(computed_signature, received_signature):
        app.logger.error("Webhook signature verification failed.")
        return jsonify({"error": "Signature mismatch"}), 400

    # 2. Process the payment data
    order_data = webhook_data.get('data', {}).get('order', {})
    payment_status = order_data.get('order_status')
    
    if payment_status == 'PAID':
        user_id = order_data.get('order_tags', {}).get('internal_user_id')
        if not user_id:
            app.logger.error("User ID not found in webhook order_tags.")
            return jsonify({"status": "error", "message": "User ID missing"}), 400
            
        order_note = order_data.get('order_note', '')
        
        # Check if it's an annual plan or credit purchase
        if "Annual Subscription" in order_note:
            # 3. Allot an activation key for an annual plan
            try:
                # Find an unused key
                keys_query = firebase.db.collection('activation_keys').where('status', '==', 'UNUSED').limit(1).get()
                if keys_query:
                    key_doc = keys_query[0]
                    key_id = key_doc.id
                    
                    # Call your FirebaseManager function to activate the user
                    firebase.activate_user(user_id, key_id)
                else:
                    app.logger.error("No unused activation keys available!")
            except Exception as e:
                app.logger.error(f"Error activating user {user_id}: {e}")

        elif "File Credits" in order_note:
            # 4. Add credits for pay-per-file purchase
            amount = float(order_data.get('order_amount', 0))
            credits_to_add = int(amount) # Assuming 1 Rupee = 1 Credit
            try:
                # Call your FirebaseManager function to add credits
                firebase.add_user_credits(user_id, credits_to_add)
            except Exception as e:
                app.logger.error(f"Error adding credits to user {user_id}: {e}")

    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
