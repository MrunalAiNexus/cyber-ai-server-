# app.py
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
import numpy as np
import joblib
import requests
import tensorflow as tf
import traceback
import time
from collections import deque
from wifi_scanner import scan_wifi
from vault import save_password, load_vault, decrypt_password
from hibp import pwned_password_count, pwned_email_breaches
from flask import send_from_directory
import os
from db import conn, cursor
import hashlib
from intruder_capture import capture_intruder, INTRUDER_DIR


# --------- Config ---------
HOST = "0.0.0.0"
PORT = 5000
MAX_EVENTS = 200  # keep last N events in memory for dashboard

# --------- Flask + SocketIO ---------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "dev-only")
socketio = SocketIO(app, cors_allowed_origins="*")  # uses eventlet/gevent when available

# --------- Load ML artifacts ---------
try:
    scaler = joblib.load("scaler.pkl")
except Exception as e:
    print(f"[ERROR] Could not load scaler.pkl → {e}")
    scaler = None

try:
    with open("threshold.txt", "r") as f:
        THRESHOLD = float(f.read().strip())
except Exception as e:
    print(f"[ERROR] Could not load threshold.txt → {e}")
    THRESHOLD = 0.0

try:
    interpreter = tf.lite.Interpreter(model_path="autoencoder_quant.tflite")
    interpreter.allocate_tensors()
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()
except Exception as e:
    print(f"[ERROR] Could not load TFLite model → {e}")
    interpreter = None
    input_details = output_details = None

# --------- In-memory events queue ---------
events = deque(maxlen=MAX_EVENTS)

# Utility: add event and broadcast
def push_event(evt: dict):
    events.appendleft(evt)  # newest first
    # Broadcast to connected dashboard clients
    socketio.emit('new_event', evt, namespace='/dashboard')
#===========Register==================#
import bcrypt 

@app.route("/register", methods=["POST"])
def register():
    data = request.json or {}

    full_name = data.get("full_name")
    email = data.get("email")
    password = data.get("password")

    if not all([full_name, email, password]):
        return jsonify({"status": "ERROR", "msg": "All fields required"}), 400

    email = email.lower().strip()

    try:
        # Check if email exists
        cursor.execute("SELECT 1 FROM USERS WHERE EMAIL = :1", [email])
        if cursor.fetchone():
            return jsonify({"status": "ERROR", "msg": "Email already registered"}), 409

        hashed = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt()
        ).decode()

        cursor.execute("""
            INSERT INTO USERS (FULL_NAME, EMAIL, PASSWORD_HASH, CREATED_AT)
            VALUES (:1, :2, :3, SYSDATE)
        """, [full_name, email, hashed])

        conn.commit()
        return jsonify({"status": "OK", "msg": "Registration successful"})

    except Exception:
        conn.rollback()
        return jsonify({"status": "ERROR", "msg": "Registration failed"}), 500

# ===================== LOGIN =====================
import bcrypt

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"status": "ERROR", "msg": "Missing credentials"}), 400

    email = email.lower().strip()

    try:
        cursor.execute("""
            SELECT FULL_NAME, PASSWORD_HASH
            FROM USERS
            WHERE EMAIL = :1
        """, [email])

        user = cursor.fetchone()

        if not user:
            capture_intruder("Wrong Login Attempt")
            return jsonify({"status": "FAILED", "msg": "Invalid Email or Password!"})

        full_name, stored_hash = user

        if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
            capture_intruder("Wrong Login Attempt")
            return jsonify({"status": "FAILED", "msg": "Invalid Email or Password!"})

        return jsonify({
            "status": "OK",
            "msg": "Login Successful!",
            "name": full_name
        })

    except Exception:
        return jsonify({"status": "ERROR", "msg": "Login failed"}), 500

# --------- Forgot Password ---------#

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json or {}
    email = data.get("email", "").lower().strip()

    if not email:
        return jsonify({"status": "ERROR", "msg": "Email required"}), 400

    cursor.execute("SELECT 1 FROM USERS WHERE EMAIL = :1", [email])
    if not cursor.fetchone():
        return jsonify({"status": "ERROR", "msg": "Email not registered"}), 404

    return jsonify({"status": "OK", "msg": "Email verified"})


#----------Reset Password-------------#

import bcrypt

@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.json or {}
    email = data.get("email", "").lower().strip()
    new_password = data.get("password")

    if not email or not new_password:
        return jsonify({"status": "ERROR", "msg": "All fields required"}), 400

    hashed = bcrypt.hashpw(
        new_password.encode(), bcrypt.gensalt()
    ).decode()

    cursor.execute("""
        UPDATE USERS
        SET PASSWORD_HASH = :1
        WHERE EMAIL = :2
    """, [hashed, email])

    conn.commit()
    return jsonify({"status": "OK", "msg": "Password reset successful"})

# --------- Detection function ---------
def detect_anomaly(input_data: list):
    """
    input_data: list in the same feature order as training
    returns: (mse, is_anomaly)
    """
    if scaler is None or interpreter is None:
        raise RuntimeError("Model/scaler not loaded")

    x = scaler.transform([input_data]).astype(np.float32)
    interpreter.set_tensor(input_details[0]['index'], x)
    interpreter.invoke()
    reconstructed = interpreter.get_tensor(output_details[0]['index'])
    mse = float(np.mean(np.square(x - reconstructed)))
    is_anomaly = int(mse > THRESHOLD)
    return mse, is_anomaly

# --------- Routes ---------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/detect", methods=["POST"])
def detect():
    try:
        data = request.json or {}

        # Safely extract values with defaults
        features = [
            data.get("session_duration", 0),
            data.get("bytes_sent", 0),
            data.get("bytes_recv", 0),
            data.get("conn_count", 0),
            data.get("unique_dest_ips", 0),
            data.get("failed_logins", 0),
            data.get("new_installs", 0),
            data.get("permission_changes", 0),
            data.get("cpu_pct", 0),
            data.get("battery_drain", 0)
        ]

        mse, anomaly = detect_anomaly(features)

        evt = {
            "timestamp": int(time.time()),
            "iso_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "input": data,
            "feature_vector": features,
            "reconstruction_error": mse,
            "anomaly": bool(anomaly),
            "threshold": THRESHOLD
        }

        push_event(evt)

        return jsonify({
            "reconstruction_error": mse,
            "anomaly_detected": bool(anomaly),
            "confidence": "HIGH RISK" if anomaly else "SAFE"
        })

    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/events", methods=["GET"])
def get_events():
    # return recent events as JSON
    return jsonify(list(events))

@app.route("/wifi-scan", methods=["GET"])
def wifi_scan():
    try:
        networks = scan_wifi()
        return jsonify({
            "status": "Scan Complete",
            "networks_detected": len(networks),
            "results": networks
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# ============= ADD PASSWORD =================
@app.route("/vault/add", methods=["POST"])
def add_password():
    data = request.json
    save_password(data["service"], data["username"], data["password"])
    return jsonify({"message": "Password Stored Securely 🔐"})


# ============= GET STORED PASSWORDS ================
@app.route("/vault", methods=["GET"])
def view_vault():
    raw = load_vault()
    decrypted = [{"service": i["service"], "username": i["username"],
                  "password": decrypt_password(i["password"])} for i in raw]
    
    return jsonify({"stored": decrypted})

# Check a single password (privacy-preserving: we use k-anonymity)
@app.route("/vault/check-password", methods=["POST"])
def check_password_route():
    """
    POST JSON: { "password": "string" }
    Response: { "pwned_count": int, "pwned": bool, "message": str }
    """
    try:
        data = request.json
        password = data.get("password")
        if password is None:
            return jsonify({"error": "password field required"}), 400

        count = pwned_password_count(password)
        return jsonify({
            "pwned_count": count,
            "pwned": bool(count > 0),
            "message": "This password was found in data breaches" if count > 0 else "No matches found"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Check a single email (requires HIBP API key)
@app.route("/vault/check-email", methods=["POST"])
def check_email_route():
    """
    POST JSON: { "email": "user@example.com" }
    Response: list of breaches or info message. Requires HIBP_API_KEY env var.
    """
    try:
        data = request.json
        email = data.get("email")
        if email is None:
            return jsonify({"error": "email field required"}), 400

        breaches = pwned_email_breaches(email)
        if not breaches:
            return jsonify({"email": email, "breaches": [], "message": "No breaches found"})
        # If truncateResponse was used it'll be shorter objects; return names
        breach_names = [b["Name"] if isinstance(b, dict) and "Name" in b else str(b) for b in breaches]
        return jsonify({"email": email, "breaches": breach_names})
    except requests.HTTPError as he:
        # HIBP returns 400/429 etc in some cases; propagate message
        return jsonify({"error": str(he), "status_code": getattr(he.response, "status_code", None)}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Check all stored vault passwords (decrypts locally then checks each password via k-anonymity)
@app.route("/vault/check-all", methods=["GET"])
def check_all_vault():
    """
    Returns pwned report for each stored credential without revealing counts to public.
    """
    try:
        vault = load_vault()  # returns list of {service, username, password(encrypted)}
        results = []
        for entry in vault:
            service = entry.get("service")
            username = entry.get("username")
            enc = entry.get("password")
            try:
                pwd = decrypt_password(enc)
            except Exception as e:
                results.append({
                    "service": service,
                    "username": username,
                    "error": "decrypt_failed"
                })
                continue

            count = pwned_password_count(pwd)
            results.append({
                "service": service,
                "username": username,
                "pwned_count": count,
                "pwned": bool(count > 0)
            })

        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

# --------- Intruder images routes ---------
# add to top of file (if not present)
from flask import Flask, jsonify, send_from_directory   # <-- REQUIRED
import os

from intruder_capture import capture_intruder, INTRUDER_DIR


# --- list intruder images endpoint ---
# --- list intruder images endpoint ---
@app.route("/intruders", methods=["GET"])
def list_intruders():
    try:
        if not os.path.exists(INTRUDER_DIR):
            return jsonify({"count": 0, "images": []})

        files = [f for f in os.listdir(INTRUDER_DIR) if f.endswith(".jpg")]
        files.sort(reverse=True)

        images = [f"/intruder-image/{file}" for file in files]
        return jsonify({"count": len(images), "images": images})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

import cv2
# --- serve single intruder image ---
INTRUDER_DIR = "intruders"

# Serve an image from the intruders folder
@app.route("/intruder-image/<filename>")
def get_intruder_image(filename):
    return send_from_directory(INTRUDER_DIR, filename)



# --------- SocketIO namespace handlers (optional) ---------
@socketio.on('connect', namespace='/dashboard')
def on_connect():
    # send initial batch of events on connect
    emit('init', list(events))

@socketio.on('ping', namespace='/dashboard')
def on_ping(msg):
    emit('pong', {'msg': 'pong'})



# --------- Run server ---------
if __name__ == "__main__":
    # Use eventlet if installed for better WebSocket support:
    # pip install eventlet
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)




