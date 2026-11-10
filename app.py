from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import datetime
import pqc
import encryption
import database
import hashlib

app = Flask(__name__)
CORS(app)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

database.init_db()


# --- STATIC FILE SERVING ---

@app.route('/')
def serve_index():
    return send_from_directory('static', 'index.html')

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)


# --- REST API: CRYPTOGRAPHY CO-PROCESSOR ---

@app.route('/api/crypto/encapsulate', methods=['POST'])
def api_encapsulate():
    """
    Dual KEM encapsulation for both receiver and sender.
    Returns two ciphertexts + shared secret.
    """
    data = request.json
    if not data:
        return jsonify({"status": "error", "message": "No JSON body"}), 400
    try:
        target_username = data['target_username']
        sender_username = data['sender_username']

        target_pub_hex = database.get_public_key(target_username)
        sender_pub_hex = database.get_public_key(sender_username)

        if not target_pub_hex or not sender_pub_hex:
            raise ValueError("Public key not found for one of the users.")

        target_pub = bytes.fromhex(target_pub_hex)
        sender_pub = bytes.fromhex(sender_pub_hex)

        c_target, c_sender, shared_secret = pqc.encapsulate_dual(target_pub, sender_pub)

        return jsonify({
            "status": "success",
            "ciphertext_target": c_target.hex(),
            "ciphertext_sender": c_sender.hex(),
            "shared_secret": shared_secret.hex()
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route('/api/crypto/decapsulate', methods=['POST'])
def api_decapsulate():
    """
    Kyber decapsulation — recovers shared secret from ciphertext + secret key.
    """
    data = request.json
    if not data:
        return jsonify({"status": "error", "message": "No JSON body"}), 400
    try:
        ciphertext = bytes.fromhex(data['ciphertext'])
        secret_key = bytes.fromhex(data['secret_key'])
        shared_secret = pqc.decapsulate(ciphertext, secret_key)
        return jsonify({
            "status": "success",
            "shared_secret": shared_secret.hex()
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route('/api/crypto/encrypt', methods=['POST'])
def api_encrypt():
    """AES-256-EAX encrypt using derived shared secret."""
    data = request.json
    if not data:
        return jsonify({"status": "error", "message": "No JSON body"}), 400
    try:
        shared_secret = bytes.fromhex(data['shared_secret'])
        message = data['message']
        if not message:
            raise ValueError("Message cannot be empty")
        encrypted_b64 = encryption.encrypt_message(shared_secret, message)
        return jsonify({"status": "success", "encrypted": encrypted_b64})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route('/api/crypto/decrypt', methods=['POST'])
def api_decrypt():
    """AES-256-EAX decrypt using derived shared secret."""
    data = request.json
    if not data:
        return jsonify({"status": "error", "message": "No JSON body"}), 400
    try:
        shared_secret = bytes.fromhex(data['shared_secret'])
        encrypted_b64 = data['encrypted_message']
        decrypted_text = encryption.decrypt_message(shared_secret, encrypted_b64)
        return jsonify({"status": "success", "decrypted": decrypted_text})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


# --- SOCKET IO HANDLERS ---

@socketio.on("register")
def handle_register(data):
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        emit("register_response", {"status": "failed", "reason": "Missing fields"}, to=request.sid)
        return

    if len(username) < 3 or len(username) > 32:
        emit("register_response", {"status": "failed", "reason": "Username must be 3–32 characters"}, to=request.sid)
        return

    # Hash password before storing (bcrypt would be better; this is a demo)
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()

    public_key, secret_key = pqc.generate_keys()
    success = database.register_user(username, hashed_pw, public_key.hex())

    if success:
        emit("register_response", {
            "status": "success",
            "secret_key": secret_key.hex()
        }, to=request.sid)
    else:
        emit("register_response", {"status": "failed"}, to=request.sid)


@socketio.on("login")
def handle_login(data):
    username = data.get("username", "").strip()
    password = data.get("password", "")

    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    valid = database.login_user(username, hashed_pw)

    if valid:
        database.update_last_seen(username, "Online")
        emit("login_response", {"status": "success", "username": username}, to=request.sid)
        socketio.emit("status_update", {"username": username, "status": "Online"})
        contacts = database.get_contacts(username)
        emit("contacts", contacts, to=request.sid)
    else:
        emit("login_response", {"status": "failed"}, to=request.sid)


@socketio.on("logout")
def handle_logout(data):
    username = data.get("username")
    if username:
        time_str = datetime.datetime.now().strftime("%H:%M")
        database.update_last_seen(username, time_str)
        socketio.emit("status_update", {"username": username, "status": f"Last seen at {time_str}"})


@socketio.on("disconnect")
def handle_disconnect():
    pass


@socketio.on("request_public_key")
def handle_request_public_key(data):
    target = data.get("target_username")
    pub_key_hex = database.get_public_key(target) if target else None
    emit("public_key_response", {"target": target, "public_key": pub_key_hex}, to=request.sid)


@socketio.on("request_contacts")
def handle_request_contacts(data):
    username = data.get("username")
    if username:
        contacts = database.get_contacts(username)
        emit("contacts", contacts, to=request.sid)


@socketio.on("message")
def handle_message(data):
    sender = data.get("sender")
    receiver = data.get("receiver")
    ciphertext = data.get("ciphertext", "")
    payload = data.get("payload", "")

    if not sender or not receiver or not payload:
        return

    packed_message = f"{ciphertext}|{payload}"
    time_str = datetime.datetime.now().strftime("%H:%M")
    database.save_message(sender, receiver, packed_message, time_str)

    socketio.emit("message", {
        "sender": sender,
        "receiver": receiver,
        "packed_message": packed_message,
        "time": time_str,
        "is_read": False
    })


@socketio.on("mark_read")
def handle_mark_read(data):
    sender = data.get("sender")
    receiver = data.get("receiver")
    if sender and receiver:
        database.mark_messages_read(sender, receiver)
        socketio.emit("read_receipt", {"viewer": receiver, "target": sender})


@socketio.on("load_chat")
def handle_load_chat(data):
    currentUser = data.get("currentUser", data.get("receiver"))
    selectedUser = data.get("selectedUser", data.get("sender"))

    if not currentUser or not selectedUser:
        return

    database.mark_messages_read(selectedUser, currentUser)
    socketio.emit("read_receipt", {"viewer": currentUser, "target": selectedUser})

    history = database.get_private_messages(currentUser, selectedUser)
    emit("chat_history", history, to=request.sid)


if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000, debug=True)
