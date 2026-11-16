# backend/networking.py
import socket
import json
import threading
import uuid
import time
from collections import defaultdict, OrderedDict

def get_auto_bind_ip():
    """Automatically detects the active LAN/Hotspot IPv4 address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            hostname_ip = socket.gethostbyname(socket.gethostname())
            if not hostname_ip.startswith("127."):
                return hostname_ip
        except Exception:
            pass
    return "127.0.0.1"

BIND_IP = get_auto_bind_ip()
SUBNET_BASE = ".".join(BIND_IP.split(".")[:3]) + "."
UDP_PORT = 7777

# ==========================================
# RAM TRACKERS & SECURITY REGISTRIES
# ==========================================
MAX_SEEN_CACHE = 2000
seen_messages = OrderedDict()
seen_messages_lock = threading.Lock()

# Smart Peer Routing Table: { "CALLSIGN": "192.168.x.x" }
peer_routing_table = {}
peer_table_lock = threading.Lock()

# Heuristic IDS (Intrusion Detection System)
node_traffic = defaultdict(list)
blacklisted_ips = {}  # { ip: timestamp_blacklisted }
IDS_THRESHOLD = 22    # Max unique packets per 3-second window
BLACKLIST_COOLDOWN = 60.0  # Seconds before a blocked IP is re-evaluated

def _mark_message_seen(message_id):
    """Thread-safe bounded insertion into seen_messages cache."""
    with seen_messages_lock:
        if message_id in seen_messages:
            return False
        seen_messages[message_id] = time.time()
        if len(seen_messages) > MAX_SEEN_CACHE:
            seen_messages.popitem(last=False)
        return True

def send_packet(sender_name, encrypted_payload, packet_type="CHAT", destination="ALL", ttl=3, extra_meta=None):
    """Constructs and transmits a MANET packet with multi-hop path tracking."""
    message_id = str(uuid.uuid4())

    tactical_packet = {
        "message_id": message_id,
        "sender": sender_name,
        "destination": destination,
        "type": packet_type,
        "ttl": ttl,
        "path": [sender_name],
        "timestamp": time.time(),
        "payload": encrypted_payload
    }
    if extra_meta:
        tactical_packet.update(extra_meta)

    _mark_message_seen(message_id)

    # Smart Unicast if destination peer IP is already known; otherwise broadcast/sweep
    target_ip = None
    with peer_table_lock:
        if destination != "ALL" and destination in peer_routing_table:
            target_ip = peer_routing_table[destination]

    threading.Thread(target=_transmit, args=(tactical_packet, target_ip), daemon=True).start()
    return True

def _transmit(packet_dict, specific_ip=None):
    """Transmits via direct unicast, subnet broadcast, and hotspot fallback sweep."""
    try:
        packet_bytes = json.dumps(packet_dict).encode('utf-8')
        transmitter = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        transmitter.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        if specific_ip:
            transmitter.sendto(packet_bytes, (specific_ip, UDP_PORT))
        elif BIND_IP == "127.0.0.1":
            transmitter.sendto(packet_bytes, ("127.0.0.1", UDP_PORT))
        else:
            # 1. Send to known peers first for zero-latency delivery
            with peer_table_lock:
                known_ips = set(peer_routing_table.values())
            for ip in known_ips:
                try:
                    transmitter.sendto(packet_bytes, (ip, UDP_PORT))
                except Exception:
                    pass

            # 2. Fast Hardware Subnet Broadcast
            try:
                transmitter.sendto(packet_bytes, (f"{SUBNET_BASE}255", UDP_PORT))
            except Exception:
                pass

            # 3. Hotspot client-isolation fallback sweep (skips own IP & known peers)
            if packet_dict.get("type") in ("KEY_EXCHANGE", "CHAT", "PING", "KILL_SWITCH"):
                for i in range(1, 255):
                    target_ip = f"{SUBNET_BASE}{i}"
                    if target_ip != BIND_IP and target_ip not in known_ips:
                        try:
                            transmitter.sendto(packet_bytes, (target_ip, UDP_PORT))
                        except Exception:
                            pass

        transmitter.close()
    except Exception as e:
        print(f"[-] RADAR SWEEP FAILED: {e}")

def listen_for_packets(callback_function, get_local_callsign_fn=None):
    """MANET Router + Active Heuristic IDS with live UI threat reporting."""
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        receiver.bind(("0.0.0.0", UDP_PORT))
        print(f"[*] T.A.N.T.R.A. MANET Router & IDS Active on {BIND_IP}:{UDP_PORT} (Bound 0.0.0.0)...")
    except Exception as e:
        print(f"[FATAL ERROR] Could not bind to UDP Port {UDP_PORT}: {e}")
        return

    while True:
        try:
            data, address = receiver.recvfrom(8192)
            sender_ip = address[0]
            current_time = time.time()

            # Check temporary blacklist with automatic cooldown expiration
            if sender_ip in blacklisted_ips:
                if current_time - blacklisted_ips[sender_ip] < BLACKLIST_COOLDOWN:
                    continue
                else:
                    del blacklisted_ips[sender_ip]

            # Parse packet
            try:
                packet = json.loads(data.decode('utf-8'))
            except Exception:
                packet = None

            # Deduplicate echoes BEFORE penalizing IDS counter
            if packet and isinstance(packet, dict):
                message_id = packet.get("message_id")
                if message_id and not _mark_message_seen(message_id):
                    continue
            else:
                message_id = None

            # Heuristic IDS Rate Limiting (never blacklist own interface)
            if sender_ip not in (BIND_IP, "127.0.0.1"):
                node_traffic[sender_ip] = [t for t in node_traffic[sender_ip] if current_time - t < 3.0]
                node_traffic[sender_ip].append(current_time)

                if len(node_traffic[sender_ip]) > IDS_THRESHOLD:
                    print(f"[CRITICAL] IDS TRIGGERED: UDP Flood detected from {sender_ip}. Node Blacklisted for 60s.")
                    blacklisted_ips[sender_ip] = current_time
                    callback_function(sender_ip, {
                        "type": "IDS_ALERT",
                        "sender": "IDS_FIREWALL",
                        "payload": f"UDP FLOOD BLOCKED FROM {sender_ip} ({len(node_traffic[sender_ip])} PKTS/3s)"
                    })
                    continue

            if not packet or not message_id:
                continue

            ttl = packet.get("ttl", 0)
            sender_callsign = packet.get("sender", "UNKNOWN")

            # Learn peer IP for smart routing
            if sender_callsign not in ("UNKNOWN", "SYSTEM", "IDS_FIREWALL"):
                with peer_table_lock:
                    peer_routing_table[sender_callsign] = sender_ip

            # Multi-hop relay forwarding
            if ttl > 1:
                forwarded_packet = packet.copy()
                forwarded_packet["ttl"] = ttl - 1
                local_callsign = get_local_callsign_fn() if get_local_callsign_fn else "RELAY"
                path = list(forwarded_packet.get("path", []))
                if local_callsign not in path:
                    path.append(local_callsign)
                forwarded_packet["path"] = path
                threading.Thread(target=_transmit, args=(forwarded_packet, None), daemon=True).start()

            callback_function(sender_ip, packet)

        except Exception as e:
            print(f"[-] Dropped malformed packet or encountered processing error: {e}")

def remove_peer_from_routing(callsign):
    """Removes a specific peer from the routing table when pruned or zeroized."""
    with peer_table_lock:
        peer_routing_table.pop(callsign, None)

def purge_system_memory():
    """Wipes all volatile network tracking data from RAM."""
    with seen_messages_lock:
        seen_messages.clear()
    with peer_table_lock:
        peer_routing_table.clear()
    node_traffic.clear()
    blacklisted_ips.clear()
    print("[!] NETWORK MEMORY PURGED. ZERO-FOOTPRINT ENFORCED.")