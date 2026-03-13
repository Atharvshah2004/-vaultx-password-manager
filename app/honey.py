from datetime import datetime, timezone
from app.encryption import encrypt_vault

# ============================================================
# PART 1: CREATE A HONEY PASSWORD ENTRY
# A fake credential secretly planted in the vault.
# Real users will never access this entry.
# ============================================================

# List of believable fake websites to use as honey entries
HONEY_WEBSITES = [
    "onlinebanking-secure.com",
    "paypal-verification.com",
    "my-crypto-wallet.com",
    "secure-storage-vault.com",
    "private-cloud-backup.com"
]

# List of believable fake usernames
HONEY_USERNAMES = [
    "admin_backup",
    "system_user",
    "vault_recovery",
    "master_account",
    "backup_admin"
]


def create_honey_entry(db, username: str, public_key: bytes) -> dict:
    """
    Creates a fake vault entry (honey password) for a user.
    This entry looks real but is never accessed by the real user.
    If it IS accessed, it triggers an intrusion alert.

    One honey entry is created per user during registration.
    """

    import os

    # Pick a random fake website and username
    website_index  = ord(os.urandom(1)) % len(HONEY_WEBSITES)
    username_index = ord(os.urandom(1)) % len(HONEY_USERNAMES)

    fake_website  = HONEY_WEBSITES[website_index]
    fake_username = HONEY_USERNAMES[username_index]

    # Generate a believable fake password
    fake_password = _generate_fake_password()

    # Build the fake entry string
    entry_string = (
        f"website:{fake_website}|"
        f"email:backup@{fake_website}|"
        f"username:{fake_username}|"
        f"password:{fake_password}|"
        f"notes:backup credentials"
    )

    # Encrypt it just like a real entry
    encrypted = encrypt_vault(entry_string, public_key)

    # Save to MongoDB with is_honey flag (hidden from normal vault view)
    honey_document = {
        "username": username,
        "website": fake_website,
        "encrypted_data": encrypted["encrypted_data"],
        "encrypted_aes_key": encrypted["encrypted_aes_key"],
        "iv": encrypted["iv"],
        "is_honey": True,              # Hidden flag — marks this as a trap
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "access_count": 0              # Tracks how many times it was accessed
    }

    result = db.vault.insert_one(honey_document)

    return {
        "success": True,
        "honey_id": str(result.inserted_id),
        "message": "Honey entry created"
    }


def _generate_fake_password() -> str:
    """
    Generates a believable fake password for the honey entry.
    Looks real but is never meant to be used.
    """
    import os
    import string

    # Build a character pool
    pool = string.ascii_letters + string.digits + "!@#$%"
    length = 14

    chars = []
    for _ in range(length):
        index = ord(os.urandom(1)) % len(pool)
        chars.append(pool[index])

    return "".join(chars)


# ============================================================
# PART 2: CHECK IF AN ENTRY IS A HONEY PASSWORD
# Called whenever a vault entry is accessed
# ============================================================

def check_honey_access(db, username: str, entry_id: str) -> bool:
    """
    Checks if the accessed entry is a honey password.
    If it is — logs an intrusion alert and returns True.
    Returns False for normal entries.
    """
    from bson import ObjectId

    # Look up the entry
    entry = db.vault.find_one({
        "_id": ObjectId(entry_id),
        "username": username
    })

    if not entry:
        return False

    # Check if it's a honey entry
    if entry.get("is_honey"):

        # Log the intrusion alert
        log_intrusion_alert(db, username, entry_id, entry.get("website"))

        # Increment access counter on the honey entry
        db.vault.update_one(
            {"_id": ObjectId(entry_id)},
            {"$inc": {"access_count": 1}}
        )

        return True  # 🚨 This is a honey access!

    return False  # Normal entry


# ============================================================
# PART 3: LOG INTRUSION ALERT
# Saves a detailed alert to the database
# ============================================================

def log_intrusion_alert(db, username: str, entry_id: str, website: str):
    """
    Saves an intrusion alert to the database.
    In a real system this would also send an email or SMS.
    """

    alert = {
        "type": "HONEY_PASSWORD_ACCESSED",
        "username": username,
        "honey_entry_id": entry_id,
        "honey_website": website,
        "timestamp": datetime.now(timezone.utc),
        "severity": "HIGH",
        "message": (
            f"WARNING: Honey password for '{website}' was accessed "
            f"by account '{username}'. Possible vault breach!"
        )
    }

    db.security_alerts.insert_one(alert)
    print(f"🚨 INTRUSION ALERT: {alert['message']}")


# ============================================================
# PART 4: GET ALL SECURITY ALERTS FOR A USER
# ============================================================

def get_security_alerts(db, username: str) -> list:
    """
    Returns all security alerts for a user.
    Shown in the security dashboard.
    """

    alerts = db.security_alerts.find(
        {"username": username},
        sort=[("timestamp", -1)]  # Most recent first
    )

    result = []
    for alert in alerts:
        result.append({
            "type": alert.get("type"),
            "severity": alert.get("severity"),
            "message": alert.get("message"),
            "timestamp": alert.get("timestamp", "").strftime("%Y-%m-%d %H:%M:%S")
                         if alert.get("timestamp") else ""
        })

    return result


# ============================================================
# PART 5: GET HONEY ENTRY IDs FOR A USER
# Used to hide honey entries from the normal vault list
# ============================================================

def get_honey_entry_ids(db, username: str) -> list:
    """
    Returns the IDs of all honey entries for a user.
    Used to filter them out of the normal vault display.
    """

    honey_entries = db.vault.find(
        {"username": username, "is_honey": True},
        {"_id": 1}
    )

    return [str(e["_id"]) for e in honey_entries]