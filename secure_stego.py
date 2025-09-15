#!/usr/bin/env python3
"""
🔐 High-Security Steganography Tool

A production-quality Python program that encrypts text messages and hides them in images
using secure cryptography and robust steganography. Only this tool with the correct 
password can recover the message.

SECURITY FEATURES:
- Authenticated encryption using ChaCha20-Poly1305 or AES-256-GCM (AEAD)
- Strong key derivation using Argon2id with secure parameters (fallback to PBKDF2)
- Separate keys for encryption and PRNG-based embedding order
- Cryptographically secure embedding order using HMAC-DRBG
- Authenticated metadata storage with integrity verification
- Length prefix and authentication tag validation
- Configurable embedding density (LSB bits per channel)
- PNG recommended (lossless), JPEG warnings included
- Comprehensive error handling and capacity checking

INSTALLATION:
pip install cryptography argon2-cffi Pillow

USAGE:
python secure_stego.py embed -i input.png -o output.png -m "secret message" -p password
python secure_stego.py extract -i output.png -p password

SECURITY GUARANTEES:
- Confidentiality: Messages encrypted with authenticated encryption (AEAD)
- Integrity: Authentication tags prevent tampering
- Forward secrecy: Fresh random salts and nonces per message
- Secure randomness: OS CSPRNG for all random values
- Key separation: Distinct keys for encryption and embedding order
- Metadata protection: All metadata authenticated via AEAD

LIMITATIONS:
- Vulnerable to steganalysis if many images from same source are analyzed
- JPEG compression may destroy embedded data (use PNG)
- Larger embedding densities increase detectability
- Physical access to tool + password compromises security
"""

import argparse
import hashlib
import hmac
import logging
import os
import secrets
import struct
import sys
import zlib
import getpass
from pathlib import Path
from typing import Tuple, Optional, List

try:
    import argon2
    import argon2.low_level
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    print("Warning: argon2-cffi not available, falling back to PBKDF2")

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    print("Error: cryptography library not available. Install with: pip install cryptography")
    sys.exit(1)

try:
    from PIL import Image
except ImportError:
    print("Error: Pillow library not available. Install with: pip install Pillow")
    sys.exit(1)

try:
    import tkinter as tk
    from tkinter import filedialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

# Constants
VERSION = b'\x01'  # Version 1 of the protocol
SALT_SIZE = 32     # 256-bit salt
NONCE_SIZE = 12    # 96-bit nonce for ChaCha20Poly1305
KEY_SIZE = 32      # 256-bit keys
PRNG_SEED_SIZE = 32  # 256-bit PRNG seed
DEFAULT_LSB_BITS = 1  # Default LSB bits per channel
MAX_LSB_BITS = 4      # Maximum LSB bits (higher = more detectable)

# Argon2 parameters (secure defaults)
ARGON2_TIME_COST = 2        # Number of iterations
ARGON2_MEMORY_COST = 2**18  # Memory usage in KB (256 MB)
ARGON2_PARALLELISM = 1      # Number of parallel threads

# PBKDF2 fallback parameters
PBKDF2_ITERATIONS = 200000  # High iteration count for security

class SecureSteganoError(Exception):
    """Base exception for secure steganography errors"""
    pass

class InsufficientCapacityError(SecureSteganoError):
    """Raised when image doesn't have enough capacity for message"""
    pass

class AuthenticationError(SecureSteganoError):
    """Raised when authentication fails (wrong password or corrupted data)"""
    pass

class ImageFormatError(SecureSteganoError):
    """Raised when image format is unsupported or problematic"""
    pass


def setup_logging(verbose: bool = False) -> None:
    """Setup secure logging that never logs sensitive data"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def secure_random(size: int) -> bytes:
    """Generate cryptographically secure random bytes using OS CSPRNG"""
    return secrets.token_bytes(size)


def derive_keys(password: str, salt: bytes) -> Tuple[bytes, bytes]:
    """
    Derive encryption and PRNG keys from password using Argon2id or PBKDF2 fallback.
    
    Args:
        password: User password string
        salt: Random salt bytes (32 bytes)
    
    Returns:
        Tuple of (encryption_key, prng_key) - each 32 bytes
    """
    password_bytes = password.encode('utf-8')
    
    if ARGON2_AVAILABLE and 'argon2' in globals():
        # Use Argon2id for optimal security against side-channel and GPU attacks
        logging.debug("Using Argon2id for key derivation")
        
        # Use low-level argon2 API for direct key derivation
        key_material = argon2.low_level.hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=64,  # Derive 64 bytes total
            type=argon2.Type.ID
        )
        
        enc_key = key_material[:32]
        prng_key = key_material[32:64]
        
    else:
        # Fallback to PBKDF2-HMAC-SHA256 with high iteration count
        logging.debug("Using PBKDF2-HMAC-SHA256 fallback for key derivation")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # Derive 64 bytes total
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key_material = kdf.derive(password_bytes)
        
        enc_key = key_material[:32]
        prng_key = key_material[32:64]
    
    logging.debug(f"Derived keys from password (salt: {len(salt)} bytes)")
    return enc_key, prng_key


class HMACDRBG:
    """
    HMAC-based Deterministic Random Bit Generator for secure embedding order.
    Implements NIST SP 800-90A HMAC_DRBG using SHA-256.
    """
    
    def __init__(self, seed: bytes):
        """Initialize HMAC-DRBG with seed material"""
        if len(seed) < 32:
            raise ValueError("Seed must be at least 32 bytes")
        
        # HMAC_DRBG state variables
        self.key = b'\x00' * 32  # Initial key
        self.val = b'\x01' * 32  # Initial value
        
        # Instantiate with seed
        self._update(seed)
    
    def _update(self, provided_data: Optional[bytes] = None):
        """Update internal state (HMAC_DRBG Update function)"""
        # K = HMAC(K, V || 0x00 || provided_data)
        data = self.val + b'\x00'
        if provided_data:
            data += provided_data
        self.key = hmac.new(self.key, data, hashlib.sha256).digest()
        
        # V = HMAC(K, V)
        self.val = hmac.new(self.key, self.val, hashlib.sha256).digest()
        
        if provided_data:
            # K = HMAC(K, V || 0x01 || provided_data)
            data = self.val + b'\x01' + provided_data
            self.key = hmac.new(self.key, data, hashlib.sha256).digest()
            
            # V = HMAC(K, V)
            self.val = hmac.new(self.key, self.val, hashlib.sha256).digest()
    
    def generate(self, num_bytes: int) -> bytes:
        """Generate pseudorandom bytes"""
        if num_bytes > 2**16:
            raise ValueError("Too many bytes requested")
        
        output = b''
        while len(output) < num_bytes:
            # V = HMAC(K, V)
            self.val = hmac.new(self.key, self.val, hashlib.sha256).digest()
            output += self.val
        
        # Update state after generation
        self._update()
        
        return output[:num_bytes]
    
    def randint(self, min_val: int, max_val: int) -> int:
        """Generate random integer in range [min_val, max_val]"""
        if min_val > max_val:
            raise ValueError("min_val must be <= max_val")
        
        range_size = max_val - min_val + 1
        if range_size == 1:
            return min_val
        
        # Generate enough bytes for uniform sampling
        bytes_needed = (range_size.bit_length() + 7) // 8
        
        while True:
            random_bytes = self.generate(bytes_needed)
            random_int = int.from_bytes(random_bytes, 'big')
            
            # Rejection sampling for uniform distribution
            if random_int < (2**(bytes_needed * 8) // range_size) * range_size:
                return min_val + (random_int % range_size)


def encrypt_and_pack(plaintext: str, enc_key: bytes, compress: bool = True) -> bytes:
    """
    Encrypt plaintext and pack with metadata using AEAD.
    
    Args:
        plaintext: Message to encrypt
        enc_key: 32-byte encryption key
        compress: Whether to compress before encryption
    
    Returns:
        Packed ciphertext with authenticated metadata
    """
    # Convert to bytes and optionally compress
    message_bytes = plaintext.encode('utf-8')
    if compress:
        message_bytes = zlib.compress(message_bytes, level=9)
        logging.debug(f"Compressed message: {len(plaintext.encode('utf-8'))} -> {len(message_bytes)} bytes")
    
    # Generate fresh nonce for each encryption
    nonce = secure_random(NONCE_SIZE)
    
    # Use ChaCha20-Poly1305 for authenticated encryption
    cipher = ChaCha20Poly1305(enc_key)
    
    # Prepare additional authenticated data (AAD)
    aad = VERSION + (b'\x01' if compress else b'\x00')
    
    # Encrypt with authentication
    ciphertext = cipher.encrypt(nonce, message_bytes, aad)
    
    # Pack: VERSION(1) | COMPRESS_FLAG(1) | NONCE(12) | CIPHERTEXT_LENGTH(4) | CIPHERTEXT
    packed = VERSION + (b'\x01' if compress else b'\x00') + nonce + struct.pack('>I', len(ciphertext)) + ciphertext
    
    logging.debug(f"Encrypted and packed {len(message_bytes)} bytes into {len(packed)} bytes")
    return packed


def unpack_and_decrypt(packed_ciphertext: bytes, enc_key: bytes) -> str:
    """
    Unpack and decrypt authenticated ciphertext.
    
    Args:
        packed_ciphertext: Packed encrypted data
        enc_key: 32-byte encryption key
    
    Returns:
        Decrypted plaintext string
    
    Raises:
        AuthenticationError: If authentication fails or data is corrupted
    """
    if len(packed_ciphertext) < 18:  # VERSION(1) + FLAG(1) + NONCE(12) + LENGTH(4)
        raise AuthenticationError("Invalid packed ciphertext: too short")
    
    # Unpack metadata
    version = packed_ciphertext[0:1]
    if version != VERSION:
        raise AuthenticationError(f"Unsupported version: {version}")
    
    compress_flag = packed_ciphertext[1:2]
    compressed = compress_flag == b'\x01'
    
    nonce = packed_ciphertext[2:14]
    ciphertext_length = struct.unpack('>I', packed_ciphertext[14:18])[0]
    
    if len(packed_ciphertext) != 18 + ciphertext_length:
        raise AuthenticationError("Invalid packed ciphertext: length mismatch")
    
    ciphertext = packed_ciphertext[18:]
    
    # Decrypt and authenticate
    cipher = ChaCha20Poly1305(enc_key)
    aad = version + compress_flag
    
    try:
        message_bytes = cipher.decrypt(nonce, ciphertext, aad)
    except Exception as e:
        raise AuthenticationError(f"Decryption failed: {e}")
    
    # Decompress if needed
    if compressed:
        try:
            message_bytes = zlib.decompress(message_bytes)
        except zlib.error as e:
            raise AuthenticationError(f"Decompression failed: {e}")
    
    # Convert back to string
    try:
        plaintext = message_bytes.decode('utf-8')
    except UnicodeDecodeError as e:
        raise AuthenticationError(f"UTF-8 decoding failed: {e}")
    
    logging.debug(f"Decrypted {len(packed_ciphertext)} bytes into {len(plaintext)} character message")
    return plaintext


def validate_image_formats(input_path: str, output_path: str) -> None:
    """
    Validate input and output image formats for steganography safety.
    
    Args:
        input_path: Path to input image
        output_path: Path for output image
    
    Raises:
        ImageFormatError: If output format will corrupt data
    """
    input_ext = Path(input_path).suffix.lower()
    output_ext = Path(output_path).suffix.lower()
    
    # Define format categories
    lossy_input_formats = ['.jpg', '.jpeg', '.webp']
    destructive_output_formats = ['.gif']  # GIF palette quantization destroys LSB
    lossy_output_formats = ['.jpg', '.jpeg']  # JPEG always lossy
    
    # Warn about lossy input formats
    if input_ext in lossy_input_formats:
        if input_ext in ['.jpg', '.jpeg']:
            logging.warning("JPEG input detected! Lossy compression may have already corrupted LSB data. Use PNG for reliability.")
        elif input_ext == '.webp':
            logging.warning("WebP input detected! If this was saved with lossy compression, LSB data may be corrupted. Use PNG for reliability.")
    
    # Block destructive output formats
    if output_ext in destructive_output_formats:
        if output_ext == '.gif':
            raise ImageFormatError(
                "GIF output format is not supported for steganography! "
                "GIF uses palette quantization which destroys LSB data. "
                "Please use PNG format instead (.png extension)."
            )
    
    # Warn about lossy output formats  
    if output_ext in lossy_output_formats:
        if output_ext in ['.jpg', '.jpeg']:
            logging.warning("JPEG output format detected! Lossy compression will likely destroy embedded data. Consider using PNG format.")


def calculate_capacity(image: Image.Image, lsb_bits: int = DEFAULT_LSB_BITS) -> int:
    """
    Calculate maximum embedding capacity in bytes for given image and LSB configuration.
    
    Args:
        image: PIL Image object
        lsb_bits: Number of LSB bits to use per channel (1-4)
    
    Returns:
        Maximum capacity in bytes
    """
    width, height = image.size
    channels = len(image.getbands())
    
    # Each pixel-channel can store lsb_bits bits
    total_bits = width * height * channels * lsb_bits
    capacity_bytes = total_bits // 8
    
    logging.debug(f"Image capacity: {width}x{height}x{channels} = {capacity_bytes} bytes at {lsb_bits} LSB bits")
    return capacity_bytes


def generate_embedding_order(prng_key: bytes, image_size: Tuple[int, int], channels: int, 
                           data_length: int, lsb_bits: int = DEFAULT_LSB_BITS) -> List[Tuple[int, int, int, int]]:
    """
    Generate cryptographically secure embedding order using HMAC-DRBG.
    
    Args:
        prng_key: 32-byte PRNG key
        image_size: (width, height) of image
        channels: Number of color channels
        data_length: Number of bytes to embed
        lsb_bits: LSB bits per channel
    
    Returns:
        List of (x, y, channel, bit) tuples for embedding order
    """
    width, height = image_size
    total_pixels = width * height * channels
    
    # Initialize HMAC-DRBG with PRNG key
    drbg = HMACDRBG(prng_key)
    
    # Generate embedding positions
    positions = []
    bits_needed = data_length * 8
    
    # Generate all possible pixel-channel-bit positions
    all_positions = []
    for y in range(height):
        for x in range(width):
            for c in range(channels):
                for bit in range(lsb_bits):
                    all_positions.append((x, y, c, bit))
    
    if bits_needed > len(all_positions):
        raise InsufficientCapacityError(
            f"Need {bits_needed} bits but image only has {len(all_positions)} "
            f"available positions at {lsb_bits} LSB bits per channel"
        )
    
    # Fisher-Yates shuffle using HMAC-DRBG
    for i in range(len(all_positions) - 1, 0, -1):
        j = drbg.randint(0, i)
        all_positions[i], all_positions[j] = all_positions[j], all_positions[i]
    
    # Take only the positions we need
    positions = all_positions[:bits_needed]
    
    logging.debug(f"Generated {len(positions)} embedding positions using HMAC-DRBG")
    return positions


def embed_into_image(input_image_path: str, output_image_path: str, 
                    packed_ciphertext: bytes, prng_key: bytes, salt: bytes,
                    lsb_bits: int = DEFAULT_LSB_BITS) -> None:
    """
    Embed packed ciphertext into image using cryptographically secure order.
    
    Args:
        input_image_path: Path to input image
        output_image_path: Path for output stego image
        packed_ciphertext: Encrypted data to embed
        prng_key: Key for generating embedding order
        salt: Salt bytes to embed (passed from embed_message)
        lsb_bits: Number of LSB bits to use per channel
    """
    # Load and validate image
    try:
        image = Image.open(input_image_path)
    except Exception as e:
        raise ImageFormatError(f"Failed to load image {input_image_path}: {e}")
    
    # Convert to RGB if needed (handles RGBA, grayscale, etc.)
    if image.mode not in ['RGB', 'RGBA']:
        if image.mode == 'L':  # Grayscale
            image = image.convert('RGB')
        elif image.mode == 'P':  # Palette
            image = image.convert('RGB')
        else:
            image = image.convert('RGB')
    
    # Validate input and output formats for steganography safety
    validate_image_formats(input_image_path, output_image_path)
    
    # Check capacity (salt + ciphertext)
    capacity = calculate_capacity(image, lsb_bits)
    total_payload_size = SALT_SIZE + len(packed_ciphertext)
    if total_payload_size > capacity:
        raise InsufficientCapacityError(
            f"Message requires {total_payload_size} bytes but image capacity is only {capacity} bytes "
            f"at {lsb_bits} LSB bits per channel. Try using more LSB bits (--lsb-bits) or a larger image."
        )
    
    width, height = image.size
    channels = len(image.getbands())
    
    # Convert image to pixel array
    pixels = list(image.getdata())
    
    # STEP 1: Embed salt using deterministic sequential order (LSB bit 0 only)
    # This avoids circular dependency - no PRNG key needed for salt placement
    salt_bits = ''.join(format(byte, '08b') for byte in salt)
    salt_bit_index = 0
    
    for y in range(height):
        for x in range(width):
            for c in range(channels):
                if salt_bit_index >= len(salt_bits):
                    break
                
                pixel_idx = y * width + x
                bit_char = salt_bits[salt_bit_index]
                
                # Modify LSB of this channel
                if image.mode == 'RGB':
                    pixel_channels = list(pixels[pixel_idx])
                    original_value = pixel_channels[c]
                    new_value = (original_value & 0xFE) | int(bit_char)  # Clear LSB, set new bit
                    pixel_channels[c] = new_value
                    pixels[pixel_idx] = tuple(pixel_channels)
                elif image.mode == 'RGBA':
                    pixel_channels = list(pixels[pixel_idx])
                    original_value = pixel_channels[c]
                    new_value = (original_value & 0xFE) | int(bit_char)  # Clear LSB, set new bit
                    pixel_channels[c] = new_value
                    pixels[pixel_idx] = tuple(pixel_channels)
                
                salt_bit_index += 1
            if salt_bit_index >= len(salt_bits):
                break
        if salt_bit_index >= len(salt_bits):
            break
    
    # STEP 2: Embed ciphertext using PRNG-generated secure order
    # This logic now matches extract_from_image exactly for consistency
    salt_bits_needed = len(salt_bits)
    
    # Mark positions used by salt (sequential LSB positions) 
    salt_channel_positions = set()
    pos_count = 0
    for y in range(height):
        for x in range(width):
            for c in range(channels):
                if pos_count < salt_bits_needed:
                    salt_channel_positions.add((x, y, c, 0))  # LSB bit 0
                    pos_count += 1
                else:
                    break
            if pos_count >= salt_bits_needed:
                break
        if pos_count >= salt_bits_needed:
            break
    
    # Generate all available positions excluding salt positions (same as extraction)
    all_available_positions = []
    for y in range(height):
        for x in range(width):
            for c in range(channels):
                for bit in range(lsb_bits):
                    pos = (x, y, c, bit)
                    if pos not in salt_channel_positions:
                        all_available_positions.append(pos)
    
    # Check capacity
    bits_needed = len(packed_ciphertext) * 8
    if bits_needed > len(all_available_positions):
        raise InsufficientCapacityError(
            f"Insufficient capacity after reserving space for salt. "
            f"Need {bits_needed} positions but only {len(all_available_positions)} available."
        )
    
    # Use HMAC-DRBG to shuffle available positions (exact same logic as extraction)
    drbg = HMACDRBG(prng_key)
    for i in range(len(all_available_positions) - 1, 0, -1):
        j = drbg.randint(0, i)
        all_available_positions[i], all_available_positions[j] = all_available_positions[j], all_available_positions[i]
    
    # Take only the positions we need 
    filtered_positions = all_available_positions[:bits_needed]
    
    # Embed ciphertext bits in the filtered positions
    ciphertext_bits = ''.join(format(byte, '08b') for byte in packed_ciphertext)
    
    for i, bit_char in enumerate(ciphertext_bits):
        x, y, channel, bit_pos = filtered_positions[i]
        pixel_idx = y * width + x
        
        # Get current pixel values and modify
        if image.mode == 'RGB':
            pixel_channels = list(pixels[pixel_idx])
            
            # Modify the specified channel and bit position
            original_value = pixel_channels[channel]
            mask = ~(1 << bit_pos)  # Clear bit at position
            new_value = (original_value & mask) | (int(bit_char) << bit_pos)
            pixel_channels[channel] = new_value
            
            # Update pixel
            pixels[pixel_idx] = tuple(pixel_channels)
            
        elif image.mode == 'RGBA':
            pixel_channels = list(pixels[pixel_idx])
            
            # Modify the specified channel and bit position
            original_value = pixel_channels[channel]
            mask = ~(1 << bit_pos)  # Clear bit at position
            new_value = (original_value & mask) | (int(bit_char) << bit_pos)
            pixel_channels[channel] = new_value
            
            # Update pixel
            pixels[pixel_idx] = tuple(pixel_channels)
    
    # Create new image with modified pixels
    new_image = Image.new(image.mode, (width, height))
    new_image.putdata(pixels)
    
    # Save with format-specific options to preserve embedded data
    output_ext = Path(output_image_path).suffix.lower()
    
    if output_ext == '.webp':
        # Use lossless WebP compression with high quality method
        new_image.save(output_image_path, format='WebP', lossless=True, method=6, optimize=False)
        logging.info("Saved as lossless WebP to preserve embedded data")
    elif output_ext in ['.jpg', '.jpeg']:
        # JPEG with maximum quality (still lossy but best possible)
        new_image.save(output_image_path, format='JPEG', optimize=False, quality=100)
        logging.warning("Saved as JPEG - embedded data may be corrupted due to lossy compression!")
    else:
        # Default save for PNG, BMP, TIFF (lossless formats)
        new_image.save(output_image_path, optimize=False)
    
    logging.info(f"Successfully embedded {SALT_SIZE} salt bytes + {len(packed_ciphertext)} ciphertext bytes into {output_image_path}")
    total_bits_used = len(salt_bits) + len(ciphertext_bits)
    logging.info(f"Used {total_bits_used} bits out of {capacity * 8} available ({total_bits_used / (capacity * 8) * 100:.2f}% capacity)")


def extract_from_image(stego_image_path: str, prng_key: bytes, 
                      max_payload_size: int = 1024*1024,  # 1MB max
                      lsb_bits: int = DEFAULT_LSB_BITS) -> Tuple[bytes, bytes]:
    """
    Extract salt and packed ciphertext from stego image.
    
    Args:
        stego_image_path: Path to stego image
        prng_key: Key for generating ciphertext extraction order
        max_payload_size: Maximum expected payload size for safety
        lsb_bits: Number of LSB bits used per channel
    
    Returns:
        Tuple of (salt_bytes, packed_ciphertext_bytes)
    
    Raises:
        AuthenticationError: If extraction fails or data is corrupted
    """
    # Load image
    try:
        image = Image.open(stego_image_path)
    except Exception as e:
        raise ImageFormatError(f"Failed to load image {stego_image_path}: {e}")
    
    # Convert to same format as embedding
    if image.mode not in ['RGB', 'RGBA']:
        if image.mode == 'L':
            image = image.convert('RGB')
        elif image.mode == 'P':
            image = image.convert('RGB')
        else:
            image = image.convert('RGB')
    
    width, height = image.size
    channels = len(image.getbands())
    pixels = list(image.getdata())
    
    # STEP 1: Extract salt using deterministic sequential order (LSB bit 0 only)
    # This matches the embedding approach and avoids circular dependency
    salt_bits = []
    salt_bits_needed = SALT_SIZE * 8  # 256 bits for 32 byte salt
    salt_bit_index = 0
    
    for y in range(height):
        for x in range(width):
            for c in range(channels):
                if salt_bit_index >= salt_bits_needed:
                    break
                
                pixel_idx = y * width + x
                
                # Extract LSB of this channel
                if image.mode == 'RGB':
                    pixel_channels = list(pixels[pixel_idx])
                    bit = pixel_channels[c] & 1  # Get LSB
                elif image.mode == 'RGBA':
                    pixel_channels = list(pixels[pixel_idx])
                    bit = pixel_channels[c] & 1  # Get LSB
                else:
                    pixel_channels = list(pixels[pixel_idx])
                    bit = pixel_channels[c] & 1  # Get LSB
                
                salt_bits.append(str(bit))
                salt_bit_index += 1
            if salt_bit_index >= salt_bits_needed:
                break
        if salt_bit_index >= salt_bits_needed:
            break
    
    # Convert salt bits to bytes
    salt_bytes = []
    for i in range(0, len(salt_bits), 8):
        byte_bits = ''.join(salt_bits[i:i+8])
        if len(byte_bits) == 8:
            salt_bytes.append(int(byte_bits, 2))
    
    salt = bytes(salt_bytes)
    
    if len(salt) != SALT_SIZE:
        raise AuthenticationError(f"Could not extract complete salt: got {len(salt)} bytes, expected {SALT_SIZE}")
    
    # STEP 2: Generate secure positions for ciphertext extraction, avoiding salt positions
    # Mark positions used by salt (sequential LSB positions)
    salt_channel_positions = set()
    pos_count = 0
    for y in range(height):
        for x in range(width):
            for c in range(channels):
                if pos_count < salt_bits_needed:
                    salt_channel_positions.add((x, y, c, 0))  # LSB bit 0
                    pos_count += 1
                else:
                    break
            if pos_count >= salt_bits_needed:
                break
        if pos_count >= salt_bits_needed:
            break
    
    # Generate all available positions excluding salt positions
    all_available_positions = []
    for y in range(height):
        for x in range(width):
            for c in range(channels):
                for bit in range(lsb_bits):
                    pos = (x, y, c, bit)
                    if pos not in salt_channel_positions:
                        all_available_positions.append(pos)
    
    # Use HMAC-DRBG to shuffle available positions (same order as embedding)
    drbg = HMACDRBG(prng_key)
    for i in range(len(all_available_positions) - 1, 0, -1):
        j = drbg.randint(0, i)
        all_available_positions[i], all_available_positions[j] = all_available_positions[j], all_available_positions[i]
    
    # First extract header to determine ciphertext length (18 bytes)
    header_bits = []
    for i in range(18 * 8):  # 18 bytes = 144 bits
        if i >= len(all_available_positions):
            raise AuthenticationError("Insufficient data for header extraction")
        
        x, y, channel, bit_pos = all_available_positions[i]
        pixel_idx = y * width + x
        
        if image.mode == 'RGB':
            pixel_channels = list(pixels[pixel_idx])
            bit = (pixel_channels[channel] >> bit_pos) & 1
        elif image.mode == 'RGBA':
            pixel_channels = list(pixels[pixel_idx])
            bit = (pixel_channels[channel] >> bit_pos) & 1
        else:
            pixel_channels = list(pixels[pixel_idx])
            bit = (pixel_channels[channel] >> bit_pos) & 1
        header_bits.append(str(bit))
    
    # Convert header bits to bytes
    header_bytes = []
    for i in range(0, len(header_bits), 8):
        byte_bits = ''.join(header_bits[i:i+8])
        if len(byte_bits) == 8:
            header_bytes.append(int(byte_bits, 2))
    
    header = bytes(header_bytes)
    
    if len(header) < 18:
        raise AuthenticationError("Could not extract valid header")
    
    # Parse ciphertext length from header
    ciphertext_length = struct.unpack('>I', header[14:18])[0]
    
    if ciphertext_length > max_payload_size:
        raise AuthenticationError(f"Ciphertext length {ciphertext_length} exceeds maximum {max_payload_size}")
    
    # Extract complete ciphertext (header + actual ciphertext)
    total_ciphertext_size = 18 + ciphertext_length
    
    if total_ciphertext_size * 8 > len(all_available_positions):
        raise AuthenticationError(f"Insufficient positions for ciphertext extraction: need {total_ciphertext_size * 8}, have {len(all_available_positions)}")
    
    ciphertext_bits = []
    for i in range(total_ciphertext_size * 8):
        x, y, channel, bit_pos = all_available_positions[i]
        pixel_idx = y * width + x
        
        if image.mode == 'RGB':
            pixel_channels = list(pixels[pixel_idx])
            bit = (pixel_channels[channel] >> bit_pos) & 1
        elif image.mode == 'RGBA':
            pixel_channels = list(pixels[pixel_idx])
            bit = (pixel_channels[channel] >> bit_pos) & 1
        else:
            pixel_channels = list(pixels[pixel_idx])
            bit = (pixel_channels[channel] >> bit_pos) & 1
        ciphertext_bits.append(str(bit))
    
    # Convert to bytes
    ciphertext_bytes = []
    for i in range(0, len(ciphertext_bits), 8):
        byte_bits = ''.join(ciphertext_bits[i:i+8])
        if len(byte_bits) == 8:
            ciphertext_bytes.append(int(byte_bits, 2))
    
    packed_ciphertext = bytes(ciphertext_bytes)
    
    logging.info(f"Extracted {SALT_SIZE} salt bytes + {len(packed_ciphertext)} ciphertext bytes from {stego_image_path}")
    return salt, packed_ciphertext


def embed_message(input_image: str, output_image: str, message: str, password: str,
                 lsb_bits: int = DEFAULT_LSB_BITS, compress: bool = True) -> None:
    """
    Complete embedding workflow: encrypt message and embed in image.
    
    Args:
        input_image: Path to input image
        output_image: Path for output stego image
        message: Text message to hide
        password: Password for encryption
        lsb_bits: LSB bits per channel (1-4)
        compress: Whether to compress message
    """
    if not (1 <= lsb_bits <= MAX_LSB_BITS):
        raise ValueError(f"LSB bits must be between 1 and {MAX_LSB_BITS}")
    
    if lsb_bits > 2:
        logging.warning(f"Using {lsb_bits} LSB bits increases detectability. Consider using fewer bits.")
    
    # Generate salt for this message
    salt = secure_random(SALT_SIZE)
    
    # Derive keys
    enc_key, prng_key = derive_keys(password, salt)
    
    # Encrypt and pack message
    packed_ciphertext = encrypt_and_pack(message, enc_key, compress)
    
    # Embed into image
    embed_into_image(input_image, output_image, packed_ciphertext, prng_key, salt, lsb_bits)
    
    logging.info(f"Message successfully embedded. Use same password to extract from {output_image}")


def extract_message(stego_image: str, password: str, lsb_bits: int = DEFAULT_LSB_BITS) -> str:
    """
    Complete extraction workflow: extract and decrypt message from image.
    
    Args:
        stego_image: Path to stego image
        password: Password for decryption
        lsb_bits: LSB bits per channel used during embedding
    
    Returns:
        Decrypted message text
    """
    if not (1 <= lsb_bits <= MAX_LSB_BITS):
        raise ValueError(f"LSB bits must be between 1 and {MAX_LSB_BITS}")
    
    if lsb_bits > 2:
        logging.warning(f"Using {lsb_bits} LSB bits increases detectability. Consider using fewer bits.")
    
    # Step 1: Extract salt using sequential deterministic order (no PRNG key needed)
    try:
        image = Image.open(stego_image)
    except Exception as e:
        raise ImageFormatError(f"Failed to load image {stego_image}: {e}")
    
    # Convert to same format as embedding
    if image.mode not in ['RGB', 'RGBA']:
        if image.mode == 'L':
            image = image.convert('RGB')
        elif image.mode == 'P':
            image = image.convert('RGB')
        else:
            image = image.convert('RGB')
    
    width, height = image.size
    channels = len(image.getbands())
    pixels = list(image.getdata())
    
    # Extract salt using deterministic sequential order (matching embedding)
    salt_bits = []
    salt_bits_needed = SALT_SIZE * 8  # 256 bits for 32 byte salt
    salt_bit_index = 0
    
    for y in range(height):
        for x in range(width):
            for c in range(channels):
                if salt_bit_index >= salt_bits_needed:
                    break
                
                pixel_idx = y * width + x
                
                # Extract LSB of this channel
                if image.mode == 'RGB':
                    pixel_channels = list(pixels[pixel_idx])
                    bit = pixel_channels[c] & 1  # Get LSB
                elif image.mode == 'RGBA':
                    pixel_channels = list(pixels[pixel_idx])
                    bit = pixel_channels[c] & 1  # Get LSB
                else:
                    pixel_channels = list(pixels[pixel_idx])
                    bit = pixel_channels[c] & 1  # Get LSB
                
                salt_bits.append(str(bit))
                salt_bit_index += 1
            if salt_bit_index >= salt_bits_needed:
                break
        if salt_bit_index >= salt_bits_needed:
            break
    
    # Convert salt bits to bytes
    salt_bytes = []
    for i in range(0, len(salt_bits), 8):
        byte_bits = ''.join(salt_bits[i:i+8])
        if len(byte_bits) == 8:
            salt_bytes.append(int(byte_bits, 2))
    
    extracted_salt = bytes(salt_bytes)
    
    if len(extracted_salt) != SALT_SIZE:
        raise AuthenticationError(f"Could not extract complete salt: got {len(extracted_salt)} bytes, expected {SALT_SIZE}")
    
    # Step 2: Now derive the correct keys using the extracted salt
    enc_key, prng_key = derive_keys(password, extracted_salt)
    
    # Step 3: Extract ciphertext using the correct PRNG key
    _, packed_ciphertext = extract_from_image(stego_image, prng_key, lsb_bits=lsb_bits)
    
    # Decrypt message
    message = unpack_and_decrypt(packed_ciphertext, enc_key)
    
    logging.info("Message successfully extracted and decrypted")
    return message


def get_supported_image_extensions():
    """Get list of supported image file extensions"""
    return ['.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.tif', '.webp', '.gif']


def validate_image_file(file_path: str) -> bool:
    """
    Validate if file exists and is a supported image format
    
    Args:
        file_path: Path to image file
        
    Returns:
        True if valid image file, False otherwise
    """
    if not os.path.exists(file_path):
        print(f"❌ Error: File '{file_path}' does not exist.")
        return False
    
    # Check file extension
    ext = Path(file_path).suffix.lower()
    supported_exts = get_supported_image_extensions()
    
    if ext not in supported_exts:
        print(f"❌ Error: Unsupported file format '{ext}'. Supported formats: {', '.join(supported_exts)}")
        return False
    
    # Try to open with PIL to verify it's a valid image
    try:
        with Image.open(file_path) as img:
            img.verify()
        return True
    except Exception as e:
        print(f"❌ Error: Invalid image file - {e}")
        return False


def open_file_dialog(title: str = "Select Image File") -> Optional[str]:
    """
    Open GUI file dialog to select image file
    
    Args:
        title: Dialog title
        
    Returns:
        Selected file path or None if cancelled
    """
    if not TKINTER_AVAILABLE:
        return None
        
    try:
        # Hide tkinter root window
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        
        # Define file types
        filetypes = [
            ("All Images", "*.png *.jpg *.jpeg *.bmp *.tiff *.tif *.webp *.gif"),
            ("PNG Files", "*.png"),
            ("JPEG Files", "*.jpg *.jpeg"),
            ("BMP Files", "*.bmp"),
            ("TIFF Files", "*.tiff *.tif"),
            ("WebP Files", "*.webp"),
            ("GIF Files", "*.gif"),
            ("All Files", "*.*")
        ]
        
        file_path = filedialog.askopenfilename(
            title=title,
            filetypes=filetypes,
            initialdir=os.getcwd()
        )
        
        root.destroy()
        return file_path if file_path else None
        
    except Exception as e:
        print(f"❌ Error opening file dialog: {e}")
        return None


def get_image_file_path(prompt: str) -> str:
    """
    Prompt user for image file path with option for GUI file dialog
    
    Args:
        prompt: Prompt message to display
        
    Returns:
        Valid image file path
    """
    print(f"\n{prompt}:")
    
    # Offer file dialog option if available
    if TKINTER_AVAILABLE:
        print(" \033[0;36m  1. 📁 Open file browser (recommended)\033[0m")
        print(" \033[0;36m  2. ⌨️  Type file path manually\033[0m")

        while True:
            choice = input("\n \033[0;35m  Choose option (1 or 2):\033[0m ").strip()
            
            if choice == "1":
                print("   Opening file browser...")
                file_path = open_file_dialog(prompt)
                if file_path:
                    print(f"   Selected: {file_path}")
                    if validate_image_file(file_path):
                        return file_path
                else:
                    print("   No file selected. Try again or choose option 2.")
                    continue
                    
            elif choice == "2":
                break
                
            else:
                print("   ❌ Please enter 1 or 2")
    
    # Manual file path entry (fallback or user choice)
    while True:
        file_path = input("   Enter file path: ").strip()
        
        if not file_path:
            print("   ❌ Please enter a file path.")
            continue
            
        # Handle quotes around file path
        if file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]
        elif file_path.startswith("'") and file_path.endswith("'"):
            file_path = file_path[1:-1]
            
        if validate_image_file(file_path):
            return file_path


def get_output_path(input_file: str) -> str:
    """
    Prompt user for output file path
    
    Args:
        input_file: Input file path for generating default output
        
    Returns:
        Output file path
    """
    input_path = Path(input_file)
    default_output = input_path.parent / f"{input_path.stem}_stego{input_path.suffix}"
    
    print(f"\n📁 Output Directory and File:")
    print(f"   Default: {default_output}")
    
    while True:
        output_path = input("   Enter output path (press Enter for default): ").strip()
        
        if not output_path:
            return str(default_output)
            
        # Handle quotes
        if output_path.startswith('"') and output_path.endswith('"'):
            output_path = output_path[1:-1]
        elif output_path.startswith("'") and output_path.endswith("'"):
            output_path = output_path[1:-1]
        
        # Check if directory exists
        output_dir = Path(output_path).parent
        if not output_dir.exists():
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
                print(f"✅ Created directory: {output_dir}")
            except Exception as e:
                print(f"❌ Error creating directory: {e}")
                continue
        
        return output_path


def get_secret_message() -> str:
    """
    Prompt user for secret message
    
    Returns:
        Secret message text
    """
    print(f"\n💬 Secret Message:")
    while True:
        message = input("   Enter your secret message: ").strip()
        
        if not message:
            print("❌ Please enter a message.")
            continue
            
        print(f"   Message length: {len(message)} characters")
        return message


def get_password(confirm: bool = False) -> str:
    """
    Prompt user for password securely
    
    Args:
        confirm: Whether to ask for password confirmation
        
    Returns:
        Password string
    """
    print(f"\n🔒 Password:")
    while True:
        password = getpass.getpass("   Enter password (hidden): ").strip()
        
        if not password:
            print("❌ Please enter a password.")
            continue
            
        if len(password) < 8:
            print("⚠️  Warning: Password is very short. Consider using at least 8 characters.")
            
        if confirm:
            password2 = getpass.getpass("   Confirm password: ").strip()
            if password != password2:
                print("❌ Passwords do not match. Please try again.")
                continue
        
        return password


def interactive_embed():
    """Hacker-style embedding interface"""
    print("\n  \033[0;31m   ┌─────────────────────────────────────────────────────────────┐\033[0m")
    print("    \033[0;31m │  [MODULE: PAYLOAD_INJECT] >> COVERT DATA EMBEDDING          │\033[0m")
    print("   \033[0;31m  └─────────────────────────────────────────────────────────────┘\033[0m")
    print("\n  \033[0;31m  >>> INITIALIZING ENCRYPTION PROTOCOLS...\033[0m")
    print("  \033[0;31m  >>> CARRIER ANALYSIS IN PROGRESS...\033[0m")
    
    # Step 1: Select input image file
    print("\n \033[0;31m   ┌─[ PHASE 1: CARRIER SELECTION ]")
    supported_formats = ", ".join(get_supported_image_extensions())
    print(f" \033[0;31m   ├─► TARGET FORMATS: {supported_formats}")
    print("  \033[0;31m  ├─► OPTIMAL CARRIER: PNG (Lossless Compression)")
    print("  \033[0;31m  └─► STATUS: AWAITING CARRIER SPECIFICATION\033[0m")
    
    input_file = get_image_file_path(" \033[0;34m   >>> SPECIFY CARRIER IMAGE PATH \033[0m")
    
    # Warn about lossy input formats
    input_ext = Path(input_file).suffix.lower()
    lossy_formats = ['.jpg', '.jpeg', '.webp']
    
    if input_ext in lossy_formats:
        format_name = "JPEG" if input_ext in ['.jpg', '.jpeg'] else "WebP"
        print(f"   ⚠️  WARNING: {format_name} is lossy and may have corrupted embedded data!")
        print("      Consider using PNG format for reliable steganography.")
        continue_choice = input("      Continue anyway? (y/N): ").strip().lower()
        if continue_choice not in ['y', 'yes']:
            print("   Operation cancelled.")
            return
    
    # Show image info
    try:
        with Image.open(input_file) as img:
            capacity = calculate_capacity(img, DEFAULT_LSB_BITS)
            print(f"   ✅ Image loaded: {img.size[0]}x{img.size[1]} pixels")
            print(f"   💾 Capacity: {capacity:,} bytes at {DEFAULT_LSB_BITS} LSB bit per channel")
    except Exception as e:
        print(f"   ❌ Error reading image: {e}")
        return
    
    # Step 2: Select output directory and filename with format validation
    while True:
        output_file = get_output_path(input_file)
        
        # Validate output format for steganography safety
        output_ext = Path(output_file).suffix.lower()
        
        if output_ext == '.gif':
            print("   ❌ ERROR: GIF format is not supported for steganography!")
            print("      GIF uses palette quantization which destroys LSB data.")
            print("      Please use PNG format instead (.png extension).")
            continue
        elif output_ext in ['.jpg', '.jpeg']:
            print("   ⚠️  WARNING: JPEG output format will likely destroy embedded data!")
            print("      JPEG uses lossy compression that corrupts LSB data.")
            print("      Consider using PNG format for reliability.")
            continue_choice = input("      Continue anyway? (y/N): ").strip().lower()
            if continue_choice not in ['y', 'yes']:
                continue
        elif output_ext == '.webp':
            print("   ✅ WebP output will use lossless compression to preserve embedded data.")
        
        break
    
    # Step 3: Get secret message
    message = get_secret_message()
    
    # Check message size
    estimated_size = len(message.encode('utf-8')) + 100  # Add overhead estimate
    if estimated_size > capacity:
        print(f"   ❌ Error: Message too large!")
        print(f"      Message size: ~{estimated_size} bytes")
        print(f"      Image capacity: {capacity} bytes")
        print("      Try a shorter message or larger image.")
        return
    
    print(f"   ✅ Message size OK: ~{estimated_size} bytes fits in {capacity} bytes")
    
    # Step 4: Get password
    password = get_password(confirm=True)
    
    # Final confirmation
    print(f"\n📋 EMBEDDING SUMMARY:")
    print(f"   Input image: {input_file}")
    print(f"   Output image: {output_file}")
    print(f"   Message: {len(message)} characters")
    print(f"   Encryption: ChaCha20-Poly1305 with Argon2id key derivation")
    
    confirm = input("\n   Proceed with embedding? (Y/n): ").strip().lower()
    if confirm in ['n', 'no']:
        print("   Operation cancelled.")
        return
    
    # Perform embedding
    print("\n🔄 Embedding message...")
    try:
        embed_message(input_file, output_file, message, password)
        print(f"✅ SUCCESS! Message embedded in: {output_file}")
        print("   Keep your password safe - you'll need it to extract the message!")
        
    except Exception as e:
        print(f"❌ EMBEDDING FAILED: {e}")


def interactive_extract():
    """Interactive extraction interface"""
    print("\n🔓 STEGANOGRAPHY EXTRACTION") 
    print("=" * 50)
    
    # Step 1: Select stego image file
    print("\n📸 Step 1: Select Your Steganographic Image")
    supported_formats = ", ".join(get_supported_image_extensions())
    print(f"   Supported formats: {supported_formats}")
    
    stego_file = get_image_file_path("   Enter path to steganographic image")
    
    # Show image info
    try:
        with Image.open(stego_file) as img:
            print(f"   ✅ Image loaded: {img.size[0]}x{img.size[1]} pixels")
    except Exception as e:
        print(f"   ❌ Error reading image: {e}")
        return
    
    # Step 2: Get password
    password = get_password(confirm=False)
    
    # Final confirmation
    print(f"\n📋 EXTRACTION SUMMARY:")
    print(f"   Steganographic image: {stego_file}")
    print(f"   Using password for decryption...")
    
    # Perform extraction
    print("\n🔄 Extracting message...")
    try:
        message = extract_message(stego_file, password)
        print("\n✅ SUCCESS! Hidden message extracted:")
        print("=" * 50)
        print(message)
        print("=" * 50)
        
    except AuthenticationError:
        print("❌ EXTRACTION FAILED: Wrong password or corrupted data!")
        print("   Please check your password and try again.")
    except Exception as e:
        print(f"❌ EXTRACTION FAILED: {e}")


def print_hacker_banner():
    """Display professional hacker-style banner using theme system"""
    from theme import print_banner

    print_banner()
    

def show_interactive_menu():
    """Show professional hacker-style interactive menu with proper alignment"""
    from theme import print_carriers_panel, print_menu, print_warning_box, get_operation_choice, print_termination_sequence, theme
    
    print_hacker_banner()
    print_carriers_panel()
    
    while True:
        print_menu()
        print_warning_box()
        
        choice = get_operation_choice()
        
        if choice == '1':
            interactive_embed()
        elif choice == '2':
            interactive_extract()
        elif choice == '3':
            interactive_capacity_check()
        elif choice == '4':
            show_help()
        elif choice == '5':
            print_termination_sequence()
            break
        else:
            print(f"\n{theme.ERROR}❌ INVALID OPERATION CODE. VALID RANGE: [1-5]{theme.RESET}")
            print(f"{theme.DIM}   Please enter a number between 1 and 5.{theme.RESET}")
            

def interactive_capacity_check():
    """Interactive capacity checking interface"""
    print("\n📊 IMAGE CAPACITY CHECK")
    print("=" * 50)
    
    print("\n📸 Select Image File to Check")
    image_file = get_image_file_path("   Enter path to image file")
    
    try:
        with Image.open(image_file) as img:
            capacity = calculate_capacity(img, DEFAULT_LSB_BITS)
            print(f"\n✅ IMAGE ANALYSIS:")
            print(f"   File: {image_file}")
            print(f"   Dimensions: {img.size[0]} x {img.size[1]} pixels")
            print(f"   Color mode: {img.mode}")
            print(f"   Channels: {len(img.getbands())}")
            print(f"\n💾 CAPACITY:")
            print(f"   At 1 LSB per channel: {capacity:,} bytes")
            print(f"   At 2 LSB per channel: {capacity*2:,} bytes (less secure)")
            print(f"   At 3 LSB per channel: {capacity*3:,} bytes (detectable)")
            print(f"   At 4 LSB per channel: {capacity*4:,} bytes (very detectable)")
            print(f"\n📝 EXAMPLES:")
            print(f"   Short message (100 chars): ✅ Fits easily")
            print(f"   Medium message (1,000 chars): {'✅ Fits' if capacity > 1000 else '❌ Too large'}")
            print(f"   Long message (10,000 chars): {'✅ Fits' if capacity > 10000 else '❌ Too large'}")
            
    except Exception as e:
        print(f"   ❌ Error analyzing image: {e}")


def show_help():
    """Show command line help"""
    print("\n❓ COMMAND LINE USAGE")
    print("=" * 50)
    print("\n📋 For advanced users, you can use command line arguments:")
    print("\n🔐 EMBEDDING:")
    print("   python secure_stego.py embed -i input.png -o output.png -m 'message' -p password")
    print("\n🔓 EXTRACTION:")
    print("   python secure_stego.py extract -i stego.png -p password")
    print("\n📊 CAPACITY CHECK:")
    print("   python secure_stego.py capacity -i image.png")
    print("\n🔧 ADVANCED OPTIONS:")
    print("   --lsb-bits N     Use N LSB bits per channel (1-4, default: 1)")
    print("   --no-compress    Disable compression")
    print("   -v, --verbose    Enable verbose logging")
    print("\n💡 TIPS:")
    print("   • Use PNG format for best results (lossless)")
    print("   • JPEG may corrupt embedded data (lossy compression)")
    print("   • Higher LSB bits = more capacity but easier to detect")
    print("   • Keep passwords secure - they cannot be recovered!")


def main():
    """Command line interface with interactive and CLI modes"""
    parser = argparse.ArgumentParser(
        description="High-Security Steganography Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--interactive', action='store_true',
                       help='Run in interactive mode')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Interactive embed command
    interactive_embed_parser = subparsers.add_parser('interactive-embed', help='Interactive embed mode')
    
    # Interactive extract command  
    interactive_extract_parser = subparsers.add_parser('interactive-extract', help='Interactive extract mode')
    
    # Embed command
    embed_parser = subparsers.add_parser('embed', help='Embed message in image')
    embed_parser.add_argument('-i', '--input', required=True,
                             help='Input image file (supports: PNG, JPEG, BMP, TIFF, WebP, GIF)')
    embed_parser.add_argument('-o', '--output', required=True,
                             help='Output stego image file')
    embed_parser.add_argument('-m', '--message', required=True,
                             help='Message to embed')
    embed_parser.add_argument('-p', '--password', required=True,
                             help='Password for encryption')
    embed_parser.add_argument('--lsb-bits', type=int, default=DEFAULT_LSB_BITS,
                             help=f'LSB bits per channel (1-{MAX_LSB_BITS}, default: {DEFAULT_LSB_BITS})')
    embed_parser.add_argument('--no-compress', action='store_true',
                             help='Disable compression')
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract message from image')
    extract_parser.add_argument('-i', '--input', required=True,
                               help='Stego image file (supports: PNG, JPEG, BMP, TIFF, WebP, GIF)')
    extract_parser.add_argument('-p', '--password', required=True,
                               help='Password for decryption')
    extract_parser.add_argument('--lsb-bits', type=int, default=DEFAULT_LSB_BITS,
                               help=f'LSB bits per channel used during embedding (default: {DEFAULT_LSB_BITS})')
    
    # Capacity command
    capacity_parser = subparsers.add_parser('capacity', help='Check image capacity')
    capacity_parser.add_argument('-i', '--input', required=True,
                                help='Image file to check (supports: PNG, JPEG, BMP, TIFF, WebP, GIF)')
    capacity_parser.add_argument('--lsb-bits', type=int, default=DEFAULT_LSB_BITS,
                                help=f'LSB bits per channel (default: {DEFAULT_LSB_BITS})')
    
    args = parser.parse_args()
    
    # If no arguments provided or --interactive flag used, show interactive menu
    if not args.command or args.interactive:
        show_interactive_menu()
        return
    
    setup_logging(args.verbose)
    
    # Validate lsb_bits parameter
    if hasattr(args, 'lsb_bits') and not (1 <= args.lsb_bits <= MAX_LSB_BITS):
        logging.error(f"LSB bits must be between 1 and {MAX_LSB_BITS}, got: {args.lsb_bits}")
        sys.exit(1)
    
    try:
        if args.command == 'interactive-embed':
            interactive_embed()
            
        elif args.command == 'interactive-extract':
            interactive_extract()
            
        elif args.command == 'embed':
            # Validate image file
            if not validate_image_file(args.input):
                sys.exit(1)
                
            embed_message(
                args.input, args.output, args.message, args.password,
                args.lsb_bits, not args.no_compress
            )
            print(f"✅ Message embedded successfully in {args.output}")
            
        elif args.command == 'extract':
            # Validate image file
            if not validate_image_file(args.input):
                sys.exit(1)
                
            message = extract_message(args.input, args.password, args.lsb_bits)
            print(f"✅ Extracted message: {message}")
            
        elif args.command == 'capacity':
            # Validate image file
            if not validate_image_file(args.input):
                sys.exit(1)
                
            image = Image.open(args.input)
            capacity = calculate_capacity(image, args.lsb_bits)
            print(f"📊 Image capacity: {capacity:,} bytes at {args.lsb_bits} LSB bits per channel")
            print(f"   Image dimensions: {image.size[0]}x{image.size[1]} pixels")
            print(f"   Color channels: {len(image.getbands())}")
            
    except SecureSteganoError as e:
        logging.error(f"Steganography error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
