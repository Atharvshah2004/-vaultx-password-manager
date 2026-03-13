from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

# ============================================================
# PART 1: RSA KEY GENERATION
# RSA gives us two keys:
# - Public key  → used to LOCK (encrypt) the AES key
# - Private key → used to UNLOCK (decrypt) the AES key
# ============================================================

def generate_rsa_keys():
    """
    Generates a new RSA public/private key pair.
    Returns both keys as bytes so they can be stored.
    """
    # Generate private key (2048 bits = strong enough for our project)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Extract the public key from the private key
    public_key = private_key.public_key()

    # Convert private key to bytes for storage
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Convert public key to bytes for storage
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_bytes, public_key_bytes


# ============================================================
# PART 2: AES ENCRYPTION (Encrypts the password vault)
# AES needs a random key and a random IV (Initialization Vector)
# IV is like a random seed that makes each encryption unique
# ============================================================

def encrypt_vault(data: str, public_key_bytes: bytes):
    """
    Encrypts vault data using hybrid encryption:
    1. Generates a random AES-256 key
    2. Encrypts the data with AES
    3. Encrypts the AES key with RSA public key
    Returns everything needed to decrypt later.
    """

    # Step 1: Generate a random 256-bit AES key (32 bytes)
    aes_key = os.urandom(32)

    # Step 2: Generate a random IV (16 bytes for AES)
    iv = os.urandom(16)

    # Step 3: Encrypt the vault data with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()

    # Step 4: Load RSA public key from bytes
    public_key = serialization.load_pem_public_key(public_key_bytes)

    # Step 5: Encrypt the AES key using RSA public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 6: Return everything as base64 strings for safe storage
    return {
        "encrypted_data": base64.b64encode(encrypted_data).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "iv": base64.b64encode(iv).decode()
    }


# ============================================================
# PART 3: AES DECRYPTION (Decrypts the password vault)
# Reverses the encryption process using the private key
# ============================================================

def decrypt_vault(encrypted_package: dict, private_key_bytes: bytes):
    """
    Decrypts vault data:
    1. Uses RSA private key to decrypt the AES key
    2. Uses the AES key to decrypt the actual data
    Returns the original plain text data.
    """

    # Step 1: Decode everything from base64 back to bytes
    encrypted_data = base64.b64decode(encrypted_package["encrypted_data"])
    encrypted_aes_key = base64.b64decode(encrypted_package["encrypted_aes_key"])
    iv = base64.b64decode(encrypted_package["iv"])

    # Step 2: Load RSA private key from bytes
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None
    )

    # Step 3: Decrypt the AES key using RSA private key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 4: Use the AES key to decrypt the actual vault data
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return decrypted_data.decode()