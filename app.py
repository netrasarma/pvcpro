from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import uuid
import os

app = Flask(__name__)
CORS(app)

# --- Configuration ---
CASHFREE_APP_ID = os.getenv("CASHFREE_APP_ID")
CASHFREE_SECRET_KEY = os.getenv("CASHFREE_SECRET_KEY")
CASHFREE_URL = "https://api.cashfree.com/pg/orders"
HEADERS = {
    "Content-Type": "application/json",
    "x-api-version": "2022-09-01",
    "x-client-id": CASHFREE_APP_ID,
    "x-client-secret": CASHFREE_SECRET_KEY
}

# --- Routes ---
@app.route("/")
def render_homepage():
    """Renders the main HTML page."""
    return render_template('index.html')

@app.route("/create_order", methods=["POST"])
def create_order():
    """Creates a Cashfree payment order."""
    if not CASHFREE_APP_ID or not CASHFREE_SECRET_KEY:
        return jsonify({"error": "Server credentials are not configured."}), 500

    data = request.json
    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    order_id = "ORDER_" + str(uuid.uuid4()).replace("-", "")[:12]

    order_data = {
        "order_id": order_id,
        "order_amount": data.get("order_amount"),
        "order_currency": "INR",
        "order_note": data.get("order_note", "PVC Pro Purchase"),
        "customer_details": {
            "customer_id": data.get("customer_id"),
            "customer_email": data.get("customer_email"),
            "customer_phone": data.get("customer_phone"),
            "customer_name": data.get("customer_name")
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))