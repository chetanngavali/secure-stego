# High-Security Steganography Tool

## Overview

This is a production-quality Python application that provides secure steganography capabilities by encrypting text messages and hiding them within image files. The tool implements military-grade cryptographic security using authenticated encryption (AEAD) with ChaCha20-Poly1305 or AES-256-GCM, combined with robust steganography techniques that embed encrypted data in image pixels using cryptographically secure random ordering. Only users with the correct password can extract and decrypt the hidden messages, making it suitable for secure communication and data protection scenarios.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

**Core Security Architecture:**
- **Authenticated Encryption (AEAD)**: Uses ChaCha20-Poly1305 or AES-256-GCM for confidentiality and integrity protection
- **Strong Key Derivation**: Implements Argon2id for secure password-to-key conversion with fallback to PBKDF2-HMAC-SHA256
- **Key Separation**: Derives distinct keys for encryption and PRNG-based embedding to prevent key reuse vulnerabilities
- **Cryptographic Randomness**: Uses OS CSPRNG (secrets module) for all random value generation

**Steganography Engine:**
- **Non-Linear Embedding**: Employs HMAC-DRBG to generate cryptographically secure random pixel ordering instead of sequential embedding
- **LSB Manipulation**: Modifies least significant bits in image pixel channels with configurable density
- **Metadata Protection**: All metadata (salt, nonce, length, version) is authenticated via AEAD to prevent tampering
- **Image Format Support**: Optimized for PNG (lossless), includes JPEG warnings due to compression artifacts

**Data Processing Pipeline:**
- **Compression**: Optional zlib compression before encryption to reduce data patterns
- **Length Prefixing**: Stores encrypted payload length for precise extraction
- **Integrity Verification**: Authentication tags validate data integrity during extraction
- **Error Correction**: Optional error-correcting codes for increased robustness

**Command-Line Interface:**
- **Interactive Interface**: Step-by-step guided interface with visual file browser integration
- **GUI File Dialog**: Native file manager integration using tkinter for easy file selection
- **Embed Operation**: Encrypts message and hides in source image to produce steganographic image
- **Extract Operation**: Retrieves and decrypts hidden message from steganographic image
- **Configuration Options**: Supports verbose logging, embedding density adjustment, and format selection

**Security Guarantees:**
- **Forward Secrecy**: Fresh random salts and nonces for each message
- **Authentication**: HMAC-based authentication prevents unauthorized modifications
- **Confidentiality**: Strong encryption protects message content
- **Integrity**: Authentication tags detect tampering attempts

## External Dependencies

**Cryptographic Libraries:**
- `cryptography`: Provides AEAD encryption algorithms (ChaCha20-Poly1305, AES-GCM) and secure key derivation functions
- `argon2-cffi`: Implements Argon2id password hashing algorithm for secure key derivation

**Image Processing:**
- `Pillow (PIL)`: Handles image file I/O, pixel manipulation, and format conversion for steganographic operations

**System Libraries:**
- `secrets`: OS-level cryptographically secure random number generation
- `hmac`: HMAC-based message authentication and deterministic random bit generation
- `hashlib`: SHA-256 and other hash functions for key derivation and integrity checking
- `zlib`: Data compression to reduce plaintext patterns before encryption
- `struct`: Binary data packing/unpacking for metadata serialization

**Optional Dependencies:**
- `reedsolo`: Reed-Solomon error correction codes for enhanced data recovery (mentioned in requirements but not imported in current code)

**INSTALLATION:**
- `command`: pip install cryptography argon2-cffi Pillow

**USAGE:**
- `command`: python secure_stego.py embed -i input.png -o output.png -m "secret message" -p password
- `command`: python secure_stego.py extract -i output.png -p password
