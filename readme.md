# T.A.N.T.R.A. — Tactical Advanced Network for Territorial Reconnaissance & Action

**T.A.N.T.R.A.** is a decentralized, offline-first, zero-footprint tactical communication and covert asset management system built in Python and JavaScript. Designed for infrastructure-denied and air-gapped environments, it operates entirely in volatile RAM—combining a multi-hop UDP Mobile Ad-hoc Network (MANET), authenticated elliptic-curve cryptography, spread-spectrum image steganography, a heuristic Intrusion Detection System (IDS), and a tamper-evident in-memory blockchain ledger.

## Core Capabilities

* **Decentralized Multi-Hop MANET (`UDP 7777`):** Automatically detects the active LAN or mobile hotspot IPv4 interface and routes packets using a three-tier strategy (Smart Unicast, hardware subnet broadcast, and `/24` client-isolation fallback sweep). Supports `TTL = 3` multi-hop relaying with path tracking, `2,000`-entry `OrderedDict` UUID deduplication, and automatic pruning of silent peers after `25.0s`.

* **Authenticated End-to-End Cryptography:** Establishes peer-to-peer session keys without a centralized Certificate Authority using **ECDH (`SECP384R1`)** authenticated with **HMAC-SHA256** and expanded via **HKDF-SHA256**. Squad broadcasts and `@CALLSIGN` peer messages are encrypted with **AES-256-GCM** (12-byte random IV, 16-byte authentication tag) backed by **PBKDF2-HMAC-SHA256** (`100,000` iterations, 128-entry RAM cache) and a `30.0s` anti-replay timestamp window.

* **In-Memory Spread-Spectrum Steganography:** Encrypts secret directives with AES-256-GCM, prepends a 32-bit length header, and scatters bits across a PNG carrier's RGB channels in RAM (`io.BytesIO`) using a deterministic `SHA-256(COMSEC Key) mod 2^32` PRNG permutation. Computes and logs real-time **MSE**, **PSNR (dB)**, and capacity utilization.

* **Heuristic IDS Firewall:** Monitors incoming packet rates per source IPv4 address over a rolling `3.0s` window. Any node exceeding `22` unique packets in `3.0s` is automatically blacklisted for `60.0s` at the socket layer, and an `IDS_GUARD` alert is committed to the ledger.

* **Zero-Footprint Volatile Blockchain & Watchdog:** Logs all uplink, key-lock, telemetry, steganography, and security events in an in-memory SHA-256 hash chain. A background watchdog thread verifies full chain integrity every `5.0s`, while an HMAC-signed `KILL_SWITCH` **Zeroize (Burn)** protocol revokes peer keys and wipes all local RAM structures on command.

* **Offline Tactical Bento HUD:** Real-time Flask-SocketIO interface bundled with local `d3.v7.min.js` (v7.9.0) and `socket.io.min.js` (v4.7.5) assets—requiring zero external internet or CDN access—featuring a force-directed multi-hop topology graph, XSS-safe DOM rendering, and a Red-Light Night-Vision **Stealth Mode**.

## Project Structure

```
T.A.N.T.R.A/
├── app.py                   # Flask + SocketIO command server, ECDH state, watchdog & API routes
├── BOOT_TANTRA.bat          # Windows launcher: verifies offline JS assets, syncs deps, boots server
├── requirements.txt         # Python dependencies
├── backend/
│   ├── __init__.py
│   ├── blockchain.py        # Volatile in-memory SHA-256 TacticalLedger & tamper simulation
│   ├── crypto.py            # SECP384R1 ECDH, HMAC-SHA256, HKDF, PBKDF2 & AES-256-GCM suite
│   ├── networking.py        # UDP 7777 MANET router, multi-hop relay & heuristic IDS firewall
│   └── stego.py             # PRNG spread-spectrum LSB steganography with MSE/PSNR metrics
├── static/
│   ├── d3.v7.min.js         # Bundled D3.js v7.9.0 for offline force-directed topology radar
│   ├── socket.io.min.js     # Bundled Socket.IO v4.7.5 client
│   ├── script.js            # HUD state management, WebSocket handlers & D3 topology renderer
│   └── style.css            # Glassmorphism Bento grid & Red-Light Stealth Mode stylesheet
└── templates/
    └── index.html           # Field Uplink gateway & three-column Tactical Command HUD
```

## Tech Stack

| Layer | Technologies |
| ----- | ----- |
| **Backend & WebSockets** | Python 3.10+, Flask `3.1.2`, Flask-SocketIO `5.6.1`, simple-websocket `1.1.0` |
| **Cryptography** | `cryptography` `46.0.5` (SECP384R1 ECDH, HMAC-SHA256, HKDF, PBKDF2, AES-256-GCM) |
| **Steganography & Math** | Pillow `11.2.1`, NumPy `2.2.6` |
| **Networking** | Python `socket` (UDP `7777`), `threading`, `collections.OrderedDict` |
| **Frontend (100% Offline)** | HTML5, CSS3, Vanilla JS, D3.js `7.9.0`, Socket.IO `4.7.5` |

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/SujalH004/TANTRA.git
cd TANTRA
```

### 2. Run on Windows (One-Click Boot)

Double-click `BOOT_TANTRA.bat` or run it from a terminal:

```bat
BOOT_TANTRA.bat
```

This script verifies that `static/socket.io.min.js` and `static/d3.v7.min.js` are present, installs dependencies from `requirements.txt`, and launches `app.py`.

### 3. Run Manually (Windows / Linux / macOS)

```bash
pip install -r requirements.txt
python app.py
```

Open **`http://127.0.0.1:5000`** in your browser. Ensure all squad terminals are connected to the same LAN, mobile hotspot, or USB-tethered subnet and share the same **COMSEC Key** (with unique **Operative Designations**).

## Usage & Tactical Commands

* **Squad Broadcast:** Type any message in the *Encrypted Telemetry* input and press **Enter** or **Tx** to broadcast using PBKDF2-derived AES-256-GCM.

* **Directed P2P Encrypted Message:** Prefix your message with `@CALLSIGN <message>` to encrypt exclusively with that peer's ECDH (`SECP384R1` + `HKDF-SHA256`) session key.

* **Mesh Latency Check:** Send `/ping` in chat to measure live mesh round-trip time (RTT) across active nodes.

* **Watchdog Tamper Demo:** Send `/tamper` in chat to corrupt the latest block in RAM; the background watchdog detects the SHA-256 hash mismatch within `5.0s` and raises a critical alert.

* **Covert Steganography:** Upload a PNG carrier image and enter a secret directive under **Covert Assets (Stego)** to download `classified_asset.png`, or upload an encoded PNG to extract and decrypt its payload.

* **Stealth Mode & Zeroize:** Click **STEALTH MODE** to switch to the red-light night-vision palette, or click **ZEROIZE (BURN)** to broadcast an authenticated `KILL_SWITCH` packet and wipe all local keys, routing tables, and ledger blocks from RAM.

## Security & Protocol Parameters

| Parameter | Configured Value | Purpose |
| ----- | ----- | ----- |
| **MANET Port** | `UDP 7777` (`0.0.0.0`) | Connectionless ad-hoc mesh transport |
| **Default Packet TTL** | `3` Hops | Multi-hop relay forwarding with loop prevention |
| **Seen-Message Cache** | `2,000` UUIDv4 entries | Bounded FIFO echo deduplication |
| **Anti-Replay Window** | `30.0 seconds` | Rejects stale or replayed UDP packets |
| **Peer Prune Timeout** | `25.0 seconds` | Removes inactive nodes and revokes stale keys |
| **Heuristic IDS Limit** | `22 packets / 3.0s` | Detects UDP flood attacks per source IP |
| **IDS Cooldown** | `60.0 seconds` | Drops traffic from blacklisted IPs at the socket |
| **Watchdog Interval** | `5.0 seconds` | Audits the volatile SHA-256 ledger for tampering |

## License

This project is licensed under the **MIT License** — see the `LICENSE` file for details.