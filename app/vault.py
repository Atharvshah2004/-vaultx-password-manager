from datetime import datetime, timezone
from app.encryption import encrypt_vault, decrypt_vault

# ============================================================
# PART 1: SAVE A PASSWORD ENTRY TO THE VAULT
# ============================================================

def add_vault_entry(db, username: str, public_key: bytes, entry: dict) -> dict:
    """
    Encrypts and saves a password entry to the vault.

    entry should contain:
    - website  : e.g. "gmail.com"
    - email    : e.g. "john@gmail.com"
    - username : e.g. "john123"
    - password : e.g. "MySecret@123"
    - notes    : e.g. "Work account" (optional)
    """

    # Step 1: Validate required fields
    if not entry.get("website"):
        return {"success": False, "message": "Website is required"}
    if not entry.get("password"):
        return {"success": False, "message": "Password is required"}

    # Step 2: Convert the entry to a string for encryption
    # We join all fields into one string separated by | symbols
    entry_string = (
        f"website:{entry.get('website', '')}|"
        f"email:{entry.get('email', '')}|"
        f"username:{entry.get('entry_username', '')}|"
        f"password:{entry.get('password', '')}|"
        f"notes:{entry.get('notes', '')}"
    )

    # Step 3: Encrypt using hybrid encryption (AES + RSA)
    encrypted = encrypt_vault(entry_string, public_key)

    # Step 4: Build the vault document for MongoDB
    vault_document = {
        "username": username,           # Owner of this entry
        "website": entry.get("website"),# Stored plain for search/display
        "encrypted_data": encrypted["encrypted_data"],
        "encrypted_aes_key": encrypted["encrypted_aes_key"],
        "iv": encrypted["iv"],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }

    # Step 5: Save to MongoDB
    result = db.vault.insert_one(vault_document)

    return {
        "success": True,
        "message": "Password saved successfully!",
        "entry_id": str(result.inserted_id)
    }


# ============================================================
# PART 2: GET ALL VAULT ENTRIES (websites list only)
# ============================================================

def get_vault_entries(db, username: str) -> list:
    """
    Returns a list of all saved websites for a user.
    Does NOT decrypt passwords — just shows the website names.
    This is used to display the vault list to the user.
    """

    entries = db.vault.find(
        {"username": username, "is_honey": {"$ne": True}}, #$ne": True this meand not equal to true because we want to exclude honey entries from the normal vault list
        {"website": 1, "created_at": 1}  # Only return website and date
    )
    
    result = []
    for entry in entries:
        result.append({
            "id": str(entry["_id"]),
            "website": entry.get("website", "Unknown"),
            "created_at": entry.get("created_at", "").strftime("%Y-%m-%d")
                          if entry.get("created_at") else ""
        })

    return result


# ============================================================
# PART 3: DECRYPT AND RETRIEVE ONE ENTRY
# ============================================================

def get_vault_entry(db, username: str, entry_id: str, private_key: bytes) -> dict:
    """
    Retrieves and decrypts a single vault entry.
    Requires the RSA private key (only available after login).
    """
    from bson import ObjectId

    # Step 1: Find the entry in MongoDB
    entry = db.vault.find_one({
        "_id": ObjectId(entry_id),
        "username": username          # Security check: user owns this entry
    })

    if not entry:
        return {"success": False, "message": "Entry not found"}

    # Step 2: Build the encrypted package
    encrypted_package = {
        "encrypted_data": entry["encrypted_data"],
        "encrypted_aes_key": entry["encrypted_aes_key"],
        "iv": entry["iv"]
    }

    # Step 3: Decrypt using the private key
    try:
        decrypted_string = decrypt_vault(encrypted_package, private_key)
    except Exception:
        return {"success": False, "message": "Decryption failed"}

    # Step 4: Parse the decrypted string back into a dict
    # Format: "website:gmail.com|email:john@gmail.com|..."
    parsed = {}
    for part in decrypted_string.split("|"):
        if ":" in part:
            key, value = part.split(":", 1)
            parsed[key] = value

    return {
        "success": True,
        "id": str(entry["_id"]),
        "website": parsed.get("website", ""),
        "email": parsed.get("email", ""),
        "entry_username": parsed.get("username", ""),
        "password": parsed.get("password", ""),
        "notes": parsed.get("notes", ""),
        "created_at": entry.get("created_at", "")
    }


# ============================================================
# PART 4: UPDATE A VAULT ENTRY
# ============================================================

def update_vault_entry(db, username: str, entry_id: str,
                       public_key: bytes, updated_entry: dict) -> dict:
    """
    Updates an existing vault entry with new encrypted data.
    """
    from bson import ObjectId

    # Verify the entry exists and belongs to this user
    existing = db.vault.find_one({
        "_id": ObjectId(entry_id),
        "username": username
    })

    if not existing:
        return {"success": False, "message": "Entry not found"}

    # Re-encrypt the updated data
    entry_string = (
        f"website:{updated_entry.get('website', '')}|"
        f"email:{updated_entry.get('email', '')}|"
        f"username:{updated_entry.get('entry_username', '')}|"
        f"password:{updated_entry.get('password', '')}|"
        f"notes:{updated_entry.get('notes', '')}"
    )

    encrypted = encrypt_vault(entry_string, public_key)

    # Update in MongoDB
    db.vault.update_one(
        {"_id": ObjectId(entry_id)},
        {"$set": {
            "website": updated_entry.get("website"),
            "encrypted_data": encrypted["encrypted_data"],
            "encrypted_aes_key": encrypted["encrypted_aes_key"],
            "iv": encrypted["iv"],
            "updated_at": datetime.now(timezone.utc)
        }}
    )

    return {"success": True, "message": "Entry updated successfully!"}


# ============================================================
# PART 5: DELETE A VAULT ENTRY
# ============================================================

def delete_vault_entry(db, username: str, entry_id: str) -> dict:
    """
    Permanently deletes a vault entry.
    """
    from bson import ObjectId

    result = db.vault.delete_one({
        "_id": ObjectId(entry_id),
        "username": username          # Security check: user owns this entry
    })

    if result.deleted_count == 0:
        return {"success": False, "message": "Entry not found"}

    return {"success": True, "message": "Entry deleted successfully!"}