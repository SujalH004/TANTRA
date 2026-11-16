# app.py
import io
import time
import threading
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO

from backend.blockchain import TacticalLedger
from backend import stego, crypto, networking

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tactical_op_secret_2026'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

system_ledger = TacticalLedger()

# ==========================================
# ECDH P2P CRYPTOGRAPHIC STATE
# ==========================================
LOCAL_PRIVATE_KEY, LOCAL_PUBLIC_PEM = crypto.generate_ecdh_keypair()
tactical_keyring = {}
peer_topology = {}  # { callsign: {"ip": ip, "path": path_list, "last_seen": ts} }
state_lock = threading.Lock()

local_operative_callsign = "UNKNOWN_OPERATIVE"
local_comsec_key = ""

REPLAY_WINDOW_SECONDS = 30.0
PEER_TIMEOUT_SECONDS = 25.0

def emit_block(block):
    """Pushes a newly created block to the UI ledger visualizer."""
    socketio.emit('ledger_update', {
        "index": block.index,
        "timestamp": time.strftime('%H:%M:%S', time.localtime(block.timestamp)),
        "agent": block.agent,
        "hash": block.hash,
        "previous_hash": block.previous_hash,
        "action": block.action
    })

def broadcast_topology():
    """Pushes the latest active peer list and multi-hop path dictionary to the UI."""
    with state_lock:
        peers = list(tactical_keyring.keys())
        details = {k: v.copy() for k, v in peer_topology.items()}
    socketio.emit('topology_update', {
        "local": local_operative_callsign,
        "peers": peers,
        "details": details
    })

def get_local_callsign():
    return local_operative_callsign

def radio_listener(sender_ip, packet):
    """Processes incoming mesh packets and dispatches real-time WebSocket events."""
    global local_operative_callsign, local_comsec_key

    packet_type = packet.get("type", "CHAT")
    peer_callsign = packet.get("sender", "UNKNOWN")

    # 1. Handle IDS Firewall Alerts even before login
    if packet_type == "IDS_ALERT":
        block = system_ledger.add_record("IDS_GUARD", packet.get("payload"))
        emit_block(block)
        socketio.emit('threat_alert', {
            "level": "CRITICAL",
            "message": packet.get("payload"),
            "timestamp": time.strftime('%H:%M:%S')
        })
        return

    if local_operative_callsign == "UNKNOWN_OPERATIVE" or peer_callsign == local_operative_callsign:
        return

    # 2. Anti-Replay Timestamp Verification
    pkt_ts = packet.get("timestamp")
    if pkt_ts and abs(time.time() - float(pkt_ts)) > REPLAY_WINDOW_SECONDS:
        msg = f"REPLAY ATTACK BLOCKED: Expired packet from {peer_callsign} ({sender_ip})"
        block = system_ledger.add_record("SEC_CORE", msg)
        emit_block(block)
        socketio.emit('threat_alert', {
            "level": "CRITICAL",
            "message": msg,
            "timestamp": time.strftime('%H:%M:%S')
        })
        return

    # Record topology path & node activity
    if peer_callsign not in ("SYSTEM", "UNKNOWN", "IDS_FIREWALL"):
        with state_lock:
            peer_topology[peer_callsign] = {
                "ip": sender_ip,
                "path": packet.get("path", [peer_callsign]),
                "last_seen": time.time()
            }

    try:
        # 3. Strictly Authenticated ECDH Handshake (No Empty-Signature Bypass)
        if packet_type == "KEY_EXCHANGE":
            peer_pem = packet.get("payload", "")
            signature = packet.get("signature", "")

            if not local_comsec_key or not crypto.verify_handshake(peer_pem, signature, local_comsec_key):
                msg = f"MITM SPOOF BLOCKED: Invalid/Missing HMAC from {peer_callsign} ({sender_ip})"
                print(f"[!] {msg}")
                block = system_ledger.add_record("SEC_CORE", msg)
                emit_block(block)
                socketio.emit('threat_alert', {
                    "level": "CRITICAL",
                    "message": msg,
                    "timestamp": time.strftime('%H:%M:%S')
                })
                return

            with state_lock:
                is_new_connection = peer_callsign not in tactical_keyring
                shared_aes_key = crypto.derive_shared_secret(LOCAL_PRIVATE_KEY, peer_pem)
                tactical_keyring[peer_callsign] = shared_aes_key

            block = system_ledger.add_record("SYSTEM", f"ECDH KEY LOCKED WITH {peer_callsign} ({sender_ip})")
            emit_block(block)
            broadcast_topology()

            if is_new_connection:
                time.sleep(0.3)
                sig = crypto.sign_handshake(LOCAL_PUBLIC_PEM, local_comsec_key)
                networking.send_packet(
                    local_operative_callsign,
                    LOCAL_PUBLIC_PEM,
                    packet_type="KEY_EXCHANGE",
                    destination=peer_callsign,
                    extra_meta={"signature": sig}
                )
            return

        # 4. Mesh Latency Ping / Pong
        if packet_type == "PING":
            networking.send_packet(
                local_operative_callsign,
                packet.get("payload"),
                packet_type="PONG",
                destination=peer_callsign
            )
            return

        if packet_type == "PONG":
            sent_ts = float(packet.get("payload", time.time()))
            rtt_ms = max(1, int((time.time() - sent_ts) * 1000))
            with state_lock:
                active_count = len(tactical_keyring) + 1
            socketio.emit('ping_update', {
                "peer": peer_callsign,
                "rtt_ms": rtt_ms,
                "active_nodes": active_count
            })
            return

        # 5. Authenticated Network-Wide Burn / Kill Switch Notification
        if packet_type == "KILL_SWITCH":
            signature = packet.get("signature", "")
            if not crypto.verify_handshake(f"ZEROIZE:{peer_callsign}", signature, local_comsec_key):
                msg = f"UNAUTHORIZED KILL_SWITCH SPOOF BLOCKED FROM {peer_callsign} ({sender_ip})"
                block = system_ledger.add_record("SEC_CORE", msg)
                emit_block(block)
                socketio.emit('threat_alert', {
                    "level": "CRITICAL",
                    "message": msg,
                    "timestamp": time.strftime('%H:%M:%S')
                })
                return

            with state_lock:
                tactical_keyring.pop(peer_callsign, None)
                peer_topology.pop(peer_callsign, None)
            networking.remove_peer_from_routing(peer_callsign)

            block = system_ledger.add_record("ZEROIZE", f"NODE {peer_callsign} EXECUTED BURN PROTOCOL - KEYS REVOKED")
            emit_block(block)
            socketio.emit('threat_alert', {
                "level": "WARNING",
                "message": f"PEER {peer_callsign} ZEROIZED. KEYS PURGED.",
                "timestamp": time.strftime('%H:%M:%S')
            })
            broadcast_topology()
            return

        # 6. Auto-Sync if unknown peer transmits
        if peer_callsign != "SYSTEM":
            with state_lock:
                known = peer_callsign in tactical_keyring
            if not known:
                sig = crypto.sign_handshake(LOCAL_PUBLIC_PEM, local_comsec_key)
                networking.send_packet(
                    local_operative_callsign,
                    LOCAL_PUBLIC_PEM,
                    packet_type="KEY_EXCHANGE",
                    destination=peer_callsign,
                    extra_meta={"signature": sig}
                )

        socketio.emit('incoming_tactical_packet', packet)

    except Exception as e:
        print(f"[-] APP LAYER ERROR: {e}")

# ==========================================
# BACKGROUND MEMORY WATCHDOG & NODE PRUNER
# ==========================================
def memory_integrity_watchdog():
    """Periodically scans the RAM blockchain for tampering and prunes dead mesh nodes."""
    while True:
        time.sleep(5.0)
        # 1. Verify RAM Blockchain Integrity
        is_valid, status_msg = system_ledger.verify_integrity()
        if not is_valid:
            print(f"[CRITICAL] RAM LEDGER TAMPERING DETECTED: {status_msg}")
            socketio.emit('threat_alert', {
                "level": "CRITICAL",
                "message": f"LEDGER CORRUPTION: {status_msg}",
                "timestamp": time.strftime('%H:%M:%S')
            })

        # 2. Prune silent/disconnected mesh peers (>25s without heartbeat)
        if local_operative_callsign != "UNKNOWN_OPERATIVE":
            now = time.time()
            stale_peers = []
            with state_lock:
                for peer, info in list(peer_topology.items()):
                    if now - info.get("last_seen", now) > PEER_TIMEOUT_SECONDS:
                        stale_peers.append(peer)
                        peer_topology.pop(peer, None)
                        tactical_keyring.pop(peer, None)

            if stale_peers:
                for peer in stale_peers:
                    networking.remove_peer_from_routing(peer)
                    socketio.emit('threat_alert', {
                        "level": "WARNING",
                        "message": f"SIGNAL LOST: {peer} DROPPED FROM MESH (TIMEOUT)",
                        "timestamp": time.strftime('%H:%M:%S')
                    })
                broadcast_topology()

# ==========================================
# STATE SYNCHRONIZATION
# ==========================================
@socketio.on('connect')
def sync_ui_on_load():
    for block in system_ledger.chain:
        emit_block(block)
    if local_operative_callsign != "UNKNOWN_OPERATIVE":
        broadcast_topology()

# ==========================================
# CORE FLASK ROUTES
# ==========================================
@app.route('/')
def load_dashboard():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def secure_login():
    global local_operative_callsign, local_comsec_key
    data = request.json or {}
    callsign = data.get("callsign", "OPERATIVE_1").strip().upper()
    local_comsec_key = data.get("key", "DEFAULT_COMSEC")
    local_operative_callsign = callsign

    block = system_ledger.add_record(callsign, f"UPLINK ESTABLISHED ON {networking.BIND_IP}")
    emit_block(block)

    sig = crypto.sign_handshake(LOCAL_PUBLIC_PEM, local_comsec_key)
    networking.send_packet(
        callsign,
        LOCAL_PUBLIC_PEM,
        packet_type="KEY_EXCHANGE",
        extra_meta={"signature": sig}
    )

    def force_radar_sync():
        time.sleep(1.0)
        broadcast_topology()

    threading.Thread(target=force_radar_sync, daemon=True).start()
    return jsonify({
        "status": "SUCCESS",
        "message": "UPLINK SECURED.",
        "latest_hash": block.hash,
        "local_ip": networking.BIND_IP
    })

@app.route('/api/comms/transmit', methods=['POST'])
def api_transmit():
    data = request.json or {}
    callsign = data.get('callsign', local_operative_callsign)
    message = data.get('message', '').strip()
    master_key = data.get('key', local_comsec_key)

    if not message or not master_key:
        return jsonify({"status": "ERROR", "message": "EMPTY PAYLOAD OR KEY"}), 400

    # Built-in Viva Presentation Commands via Chat Input
    if message.lower() == "/ping":
        networking.send_packet(callsign, str(time.time()), packet_type="PING")
        return jsonify({"status": "SUCCESS", "system_note": "MESH PING BROADCASTED"})

    if message.lower() == "/tamper":
        system_ledger.simulate_memory_tamper()
        return jsonify({"status": "SUCCESS", "system_note": "RAM CORRUPTION INJECTED (WAIT 5s FOR WATCHDOG)"})

    target_destination = "ALL"
    encryption_key = master_key

    if message.startswith('@'):
        parts = message.split(' ', 1)
        if len(parts) > 1:
            potential_target = parts[0][1:].upper()
            with state_lock:
                peer_key = tactical_keyring.get(potential_target)
            if peer_key:
                target_destination = potential_target
                encryption_key = peer_key
                message = f"[P2P ECDH->{potential_target}] {parts[1]}"
            else:
                return jsonify({"status": "ERROR", "message": f"NO ECDH KEY FOR {potential_target}"}), 400

    encrypted_payload = crypto.encrypt_message(message, encryption_key)
    success = networking.send_packet(callsign, encrypted_payload, "CHAT", destination=target_destination)

    if success:
        block = system_ledger.add_record(callsign, f"TX ENCRYPTED COMMS -> {target_destination}")
        emit_block(block)
        return jsonify({"status": "SUCCESS"})
    return jsonify({"status": "ERROR", "message": "RADIO FAILURE"}), 500

@app.route('/api/comms/sync_single', methods=['POST'])
def api_sync_single():
    data = request.json or {}
    sender = data.get('sender')
    payload = data.get('payload')
    ui_key = data.get('key', local_comsec_key)

    with state_lock:
        peer_key = tactical_keyring.get(sender)

    if peer_key:
        msg_text, success = crypto.decrypt_message(payload, peer_key)
        if success:
            return jsonify({"status": "SUCCESS", "message": msg_text, "mode": "ECDH_P2P"})

    msg_text, success = crypto.decrypt_message(payload, ui_key)
    if success:
        return jsonify({"status": "SUCCESS", "message": msg_text, "mode": "AES_SQUAD"})

    socketio.emit('threat_alert', {
        "level": "WARNING",
        "message": f"DECRYPTION FAILED FROM {sender} (KEY MISMATCH / TAMPERED)",
        "timestamp": time.strftime('%H:%M:%S')
    })
    return jsonify({"status": "ERROR"}), 403

@app.route('/api/comms/ping', methods=['POST'])
def api_ping():
    if local_operative_callsign != "UNKNOWN_OPERATIVE":
        networking.send_packet(local_operative_callsign, str(time.time()), packet_type="PING")
    with state_lock:
        active_count = len(tactical_keyring) + 1
    return jsonify({"status": "SUCCESS", "active_nodes": active_count})

@app.route('/api/system/purge', methods=['POST'])
def api_system_purge():
    global LOCAL_PRIVATE_KEY, LOCAL_PUBLIC_PEM, local_operative_callsign, local_comsec_key
    if local_operative_callsign != "UNKNOWN_OPERATIVE" and local_comsec_key:
        sig = crypto.sign_handshake(f"ZEROIZE:{local_operative_callsign}", local_comsec_key)
        networking.send_packet(
            local_operative_callsign,
            "ZEROIZE",
            packet_type="KILL_SWITCH",
            extra_meta={"signature": sig}
        )

    genesis = system_ledger.purge_ledger()
    networking.purge_system_memory()
    crypto.clear_key_cache()
    with state_lock:
        tactical_keyring.clear()
        peer_topology.clear()
    LOCAL_PRIVATE_KEY, LOCAL_PUBLIC_PEM = crypto.generate_ecdh_keypair()
    local_operative_callsign = "UNKNOWN_OPERATIVE"
    local_comsec_key = ""

    emit_block(genesis)
    return jsonify({"status": "SUCCESS"})

# ==========================================
# STEGANOGRAPHY ROUTES
# ==========================================
@app.route('/api/stego/encode', methods=['POST'])
def api_stego_encode():
    if 'image' not in request.files or 'message' not in request.form or 'key' not in request.form:
        return jsonify({"status": "ERROR", "message": "MISSING ASSET, PAYLOAD, OR KEY"}), 400

    file = request.files['image']
    secret_message = request.form['message']
    password = request.form['key']

    encrypted_payload = crypto.encrypt_message(secret_message, password)
    image_bytes = io.BytesIO(file.read())

    success, result, metrics = stego.encode_image_ram(image_bytes, encrypted_payload, password)

    if success:
        action_str = f"STEGO ENCODED (PSNR: {metrics['psnr_db']} dB | MSE: {metrics['mse']})"
        block = system_ledger.add_record(local_operative_callsign, action_str)
        emit_block(block)
        socketio.emit('stego_metrics', metrics)
        return send_file(result, mimetype='image/png', as_attachment=True, download_name='classified_asset.png')
    else:
        return jsonify({"status": "ERROR", "message": result}), 400

@app.route('/api/stego/decode', methods=['POST'])
def api_stego_decode():
    if 'image' not in request.files or 'key' not in request.form:
        return jsonify({"status": "ERROR", "message": "MISSING ASSET OR KEY"}), 400

    file = request.files['image']
    password = request.form['key']
    image_bytes = io.BytesIO(file.read())

    try:
        success, hidden_payload = stego.decode_image(image_bytes, password)
        if success:
            decrypted_message, decrypt_success = crypto.decrypt_message(hidden_payload, password)
            if decrypt_success:
                block = system_ledger.add_record(local_operative_callsign, "COVERT STEGO ASSET DECRYPTED")
                emit_block(block)
                return jsonify({"status": "SUCCESS", "message": decrypted_message}), 200
            else:
                return jsonify({"status": "ERROR", "message": "DECRYPTION FAILED: WRONG COMSEC KEY."}), 403
        else:
            return jsonify({"status": "ERROR", "message": hidden_payload}), 400
    except Exception as e:
        return jsonify({"status": "ERROR", "message": f"ASSET DECODING FAILED: {e}"}), 500

if __name__ == '__main__':
    print("\n=======================================================")
    print("[*] T.A.N.T.R.A. FIELD COMMAND SERVER INITIATED")
    print(f"[*] AUTO-DETECTED NODE IP: {networking.BIND_IP}:{networking.UDP_PORT}")
    print("[*] AUTHENTICATED ECDH + PBKDF2 + WATCHDOG: ONLINE")
    print("[*] UPLINK READY: http://127.0.0.1:5000")
    print("=======================================================\n")

    mesh_thread = threading.Thread(
        target=networking.listen_for_packets,
        args=(radio_listener, get_local_callsign),
        daemon=True
    )
    mesh_thread.start()

    watchdog_thread = threading.Thread(target=memory_integrity_watchdog, daemon=True)
    watchdog_thread.start()

    socketio.run(app, host='0.0.0.0', port=5000)