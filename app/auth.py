import os
import base64
from datetime import datetime, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from app.encryption import generate_rsa_keys

# ============================================================
# SETTINGS
# ============================================================
MAX_FAILED_ATTEMPTS = 5      # Lock after this many wrong tries
LOCKOUT_DURATION_SEC = 300   # Lock for 5 minutes (300 seconds)

# Argon2 password hasher with strong settings
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64MB
    parallelism=2
)


# ============================================================
# PART 1: MASTER PASSWORD HASHING
# ============================================================

def hash_master_password(master_password: str) -> str:
    """
    Hashes master password using Argon2id.
    The original password can NEVER be recovered from this.
    """
    return ph.hash(master_password)


def verify_master_password(stored_hash: str, master_password: str) -> bool:
    """
    Checks if the entered password matches the stored hash.
    Returns True if correct, False if wrong.
    """
    try:
        ph.verify(stored_hash, master_password)
        return True
    except VerifyMismatchError:
        return False


# ============================================================
# PART 2: KEY DERIVATION
# Turns master password into an encryption key using PBKDF2
# ============================================================

def derive_key_from_password(master_password: str, salt: bytes = None):
    """
    Derives a 256-bit encryption key from the master password.
    Always save the salt — you need it to re-derive the same key.
    """
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000
    )
    key = kdf.derive(master_password.encode())
    return key, salt


# ============================================================
# PART 3: PRIVATE KEY PROTECTION
# We encrypt the RSA private key using the derived key
# so it can be safely stored in the database
# ============================================================

def encrypt_private_key(private_key_bytes: bytes, derived_key: bytes) -> dict:
    """
    Encrypts the RSA private key using AES and the derived key.
    This way even if the database is stolen, the private key
    cannot be read without the master password.
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(private_key_bytes) + encryptor.finalize()

    return {
        "encrypted_private_key": base64.b64encode(encrypted).decode(),
        "iv": base64.b64encode(iv).decode()
    }


def decrypt_private_key(encrypted_package: dict, derived_key: bytes) -> bytes:
    """
    Decrypts the RSA private key using the derived key.
    Called when user logs in successfully.
    """
    encrypted = base64.b64decode(encrypted_package["encrypted_private_key"])
    iv = base64.b64decode(encrypted_package["iv"])

    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()


# ============================================================
# PART 4: USER REGISTRATION
# ============================================================

def register_user(db, username: str, master_password: str) -> dict:
    """
    Creates a new user account.
    Steps:
    1. Check username not already taken
    2. Hash the master password
    3. Derive encryption key from master password
    4. Generate RSA key pair
    5. Encrypt the RSA private key
    6. Save everything to MongoDB
    """

    # Step 1: Check if username already exists
    existing = db.users.find_one({"username": username})
    if existing:
        return {"success": False, "message": "Username already taken"}

    # Step 2: Hash master password for storage
    password_hash = hash_master_password(master_password)

    # Step 3: Derive encryption key from master password
    derived_key, salt = derive_key_from_password(master_password)

    # Step 4: Generate RSA key pair for this user
    private_key_bytes, public_key_bytes = generate_rsa_keys()

    # Step 5: Encrypt the private key before storing
    encrypted_private_key_package = encrypt_private_key(private_key_bytes, derived_key)

    # Step 6: Build the user document for MongoDB
    user_document = {
        "username": username,

        # Argon2 hash — for verifying master password at login
        "password_hash": password_hash,

        # Salt used to re-derive the encryption key
        "kdf_salt": base64.b64encode(salt).decode(),

        # RSA public key — stored as plain text (public = safe to store)
        "public_key": public_key_bytes.decode(),

        # RSA private key — encrypted with derived key (NEVER store plain)
        "encrypted_private_key": encrypted_private_key_package["encrypted_private_key"],
        "private_key_iv": encrypted_private_key_package["iv"],

        # Account metadata
        "created_at": datetime.now(timezone.utc),
        "failed_attempts": 0,
        "locked_until": None
    }

    # Save to MongoDB
    db.users.insert_one(user_document)

    # Plant a honey password entry for intrusion detection
    from app.honey import create_honey_entry
    create_honey_entry(db, username, public_key_bytes)

    return {"success": True, "message": "Account created successfully!"}
    

# ============================================================
# PART 5: USER LOGIN WITH BRUTE-FORCE PROTECTION
# ============================================================

def login_user(db, username: str, master_password: str) -> dict:
    """
    Logs in a user with brute-force protection.
    Steps:
    1. Find the user in database
    2. Check if account is locked
    3. Verify the master password
    4. On success: decrypt private key and return it
    5. On failure: increment failed attempts counter
    """

    # Step 1: Find the user
    user = db.users.find_one({"username": username})
    if not user:
        # Don't say "user not found" — that helps attackers enumerate usernames
        return {"success": False, "message": "Invalid username or password"}

    # Step 2: Check if account is currently locked
    if user.get("locked_until"):
        locked_until = user["locked_until"]

        # Make locked_until timezone-aware if it isn't
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        if now < locked_until:
            # Calculate remaining lockout time
            remaining = int((locked_until - now).total_seconds())
            return {
                "success": False,
                "message": f"Account locked. Try again in {remaining} seconds.",
                "locked": True
            }
        else:
            # Lockout has expired — reset the counter
            db.users.update_one(
                {"username": username},
                {"$set": {"failed_attempts": 0, "locked_until": None}}
            )

    # Step 3: Verify the master password
    password_correct = verify_master_password(user["password_hash"], master_password)

    if not password_correct:
        # Increment failed attempts
        failed = user.get("failed_attempts", 0) + 1
        update_data = {"failed_attempts": failed}

        if failed >= MAX_FAILED_ATTEMPTS:
            # Lock the account
            from datetime import timedelta
            lock_time = datetime.now(timezone.utc)
            locked_until = lock_time + timedelta(seconds=LOCKOUT_DURATION_SEC)
            update_data["locked_until"] = locked_until
            db.users.update_one({"username": username}, {"$set": update_data})
            return {
                "success": False,
                "message": f"Too many failed attempts. Account locked for {LOCKOUT_DURATION_SEC // 60} minutes.",
                "locked": True
            }

        attempts_left = MAX_FAILED_ATTEMPTS - failed
        db.users.update_one({"username": username}, {"$set": update_data})
        return {
            "success": False,
            "message": f"Invalid password — {attempts_left} attempt{'s' if attempts_left != 1 else ''} remaining before lockout.",
            "attempts_left": attempts_left,
            "locked": False
        }

    # Step 4: Password correct — re-derive the encryption key
    salt = base64.b64decode(user["kdf_salt"])
    derived_key, _ = derive_key_from_password(master_password, salt)

    # Step 5: Decrypt the RSA private key
    encrypted_package = {
        "encrypted_private_key": user["encrypted_private_key"],
        "iv": user["private_key_iv"]
    }
    private_key_bytes = decrypt_private_key(encrypted_package, derived_key)

    # Step 6: Reset failed attempts on successful login
    db.users.update_one(
        {"username": username},
        {"$set": {"failed_attempts": 0, "locked_until": None}}
    )

    return {
        "success": True,
        "message": "Login successful!",
        "username": username,
        "private_key": private_key_bytes,
        "public_key": user["public_key"].encode()
    }