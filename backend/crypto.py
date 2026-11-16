# backend/crypto.py
import base64
import hashlib
import hmac
import os
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Deterministic tactical salt for key derivation across air-gapped nodes
TACTICAL_SALT = b"TANTRA_COMSEC_SALT_2026_V2"

# Volatile RAM cache for derived keys (wiped on Zeroize)
_key_cache = {}
_cache_lock = threading.Lock()

# ==========================================
# 1. ECDH KEY EXCHANGE & MITM AUTHENTICATION
# ==========================================
def generate_ecdh_keypair():
    """Generates an Elliptic Curve (SECP384R1) private/public keypair."""
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_key, public_pem

def sign_handshake(payload_str, comsec_key):
    """Signs a tactical payload or ECDH public key with the squad COMSEC key."""
    if not payload_str or not comsec_key:
        return ""
    return hmac.new(
        comsec_key.encode('utf-8'),
        payload_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

def verify_handshake(payload_str, signature_hex, comsec_key):
    """Verifies that an incoming control packet belongs to an authorized squad member."""
    if not payload_str or not signature_hex or not comsec_key:
        return False
    expected_sig = sign_handshake(payload_str, comsec_key)
    return hmac.compare_digest(expected_sig, signature_hex)

def derive_shared_secret(private_key, peer_public_pem):
    """Derives a 256-bit shared secret using ECDH + HKDF-SHA256."""
    peer_public_key = serialization.load_pem_public_key(
        peer_public_pem.encode('utf-8'),
        backend=default_backend()
    )

    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    derived_aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=TACTICAL_SALT,
        info=b'tantra_ecdh_handshake',
        backend=default_backend()
    ).derive(shared_secret)

    return base64.urlsafe_b64encode(derived_aes_key).decode('utf-8')

# ==========================================
# 2. PBKDF2 + AES-256-GCM ENCRYPTION
# ==========================================
def generate_key(password):
    """Derives and caches a hardened 32-byte AES-256 key in volatile RAM."""
    with _cache_lock:
        if password in _key_cache:
            return _key_cache[password]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=TACTICAL_SALT,
        iterations=100_000,
        backend=default_backend()
    )
    derived = kdf.derive(password.encode('utf-8'))

    with _cache_lock:
        if len(_key_cache) > 128:
            _key_cache.clear()
        _key_cache[password] = derived

    return derived

def clear_key_cache():
    """Purges cached cryptographic keys from RAM during Zeroize."""
    with _cache_lock:
        _key_cache.clear()

def encrypt_message(message, password):
    key = generate_key(password)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    final_payload = base64.urlsafe_b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')
    return final_payload

def decrypt_message(encrypted_message, password):
    try:
        key = generate_key(password)
        raw_data = base64.urlsafe_b64decode(encrypted_message.encode('utf-8'))
        iv = raw_data[:12]
        tag = raw_data[12:28]
        ciphertext = raw_data[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        message_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return message_bytes.decode('utf-8'), True
    except InvalidTag:
        return "ERROR: INTEGRITY COMPROMISED. TAMPERING DETECTED.", False
    except Exception:
        return "ERROR: ACCESS DENIED. KEY MISMATCH.", False