# backend/stego.py
from PIL import Image
import numpy as np
import io
import hashlib
import math

def get_prng_seed(password):
    """Deterministically converts the COMSEC key into a 32-bit PRNG seed."""
    hash_hex = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return int(hash_hex, 16) % (2**32)

def encode_image_ram(image_path_or_bytes, secret_message, password):
    """
    Spread-Spectrum Steganography with 32-bit length header and PSNR/MSE evaluation.
    Returns: (success: bool, result: BytesIO|str, metrics: dict)
    """
    payload_bytes = secret_message.encode('utf-8')
    payload_bit_len = len(payload_bytes) * 8

    # 32-bit header stores exact bit length of the payload
    header_bits = format(payload_bit_len, '032b')
    payload_bits = ''.join(format(byte, '08b') for byte in payload_bytes)
    full_binary = header_bits + payload_bits
    total_bits = len(full_binary)

    try:
        img = Image.open(image_path_or_bytes).convert('RGBA')
    except Exception:
        return False, "ERROR: Target image not found or corrupted.", {}

    orig_array = np.array(img)
    stego_array = orig_array.copy()
    rgb_flat = stego_array[:, :, :3].flatten()

    if total_bits > len(rgb_flat):
        return False, "ERROR: Image capacity exceeded for this payload.", {}

    bit_array = np.array(list(full_binary), dtype=np.uint8)

    # Consistent Spread-Spectrum PRNG coordinate selection
    seed = get_prng_seed(password)
    prng = np.random.RandomState(seed)
    scattered_indices = prng.permutation(len(rgb_flat))[:total_bits]

    # Inject bits into LSB of selected channels
    rgb_flat[scattered_indices] = (rgb_flat[scattered_indices] & 254) | bit_array
    stego_array[:, :, :3] = rgb_flat.reshape(stego_array.shape[0], stego_array.shape[1], 3)

    # Calculate Academic Steganography Metrics (MSE & PSNR)
    mse = float(np.mean((orig_array[:, :, :3].astype(float) - stego_array[:, :, :3].astype(float)) ** 2))
    psnr = 100.0 if mse == 0 else round(10 * math.log10((255.0 ** 2) / mse), 2)
    capacity_used = round((total_bits / len(rgb_flat)) * 100, 4)

    metrics = {
        "mse": round(mse, 6),
        "psnr_db": psnr,
        "bits_embedded": total_bits,
        "capacity_percent": capacity_used
    }

    final_img = Image.fromarray(stego_array)
    virtual_memory_file = io.BytesIO()
    final_img.save(virtual_memory_file, format="PNG")
    virtual_memory_file.seek(0)

    return True, virtual_memory_file, metrics

def decode_image(image_path_or_bytes, password):
    """
    Fast PRNG Extraction: Uses identical permutation to read 32-bit header and payload bits.
    """
    try:
        img = Image.open(image_path_or_bytes).convert('RGBA')
    except Exception:
        return False, "ERROR: Target image not found or corrupted."

    img_array = np.array(img)
    rgb_flat = img_array[:, :, :3].flatten()
    total_channels = len(rgb_flat)

    if total_channels < 32:
        return False, "ERROR: Image too small to contain a valid header."

    seed = get_prng_seed(password)
    prng = np.random.RandomState(seed)
    permutation = prng.permutation(total_channels)

    header_indices = permutation[:32]
    header_bits = ''.join(str(b) for b in (rgb_flat[header_indices] & 1))
    payload_bit_len = int(header_bits, 2)

    if payload_bit_len <= 0 or payload_bit_len > (total_channels - 32) or payload_bit_len % 8 != 0:
        return False, "ERROR: No secured payload found, or incorrect COMSEC key."

    payload_indices = permutation[32 : 32 + payload_bit_len]
    extracted_bits = rgb_flat[payload_indices] & 1
    extracted_bytes = np.packbits(extracted_bits)

    try:
        secret_message = extracted_bytes.tobytes().decode('utf-8')
        return True, secret_message
    except UnicodeDecodeError:
        return False, "ERROR: Decryption failed or corrupted stego asset."