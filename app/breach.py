import hashlib
import requests

# ============================================================
# PART 1: CORE BREACH CHECK
# Uses HaveIBeenPwned k-anonymity API
# Never sends full password or full hash — only 5 characters
# ============================================================

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

def check_password_breach(password: str) -> dict:
    """
    Checks if a password has appeared in known data breaches.

    Uses k-anonymity — only sends first 5 chars of SHA1 hash.
    The full password NEVER leaves your machine.

    Returns:
    - breached     : True if found in breaches
    - breach_count : how many times it appeared
    - message      : human readable result
    - safe         : True if not found
    """

    # Step 1: Hash the password with SHA1
    sha1_hash = hashlib.sha1(
        password.encode('utf-8')
    ).hexdigest().upper()

    # Step 2: Split into prefix (first 5) and suffix (rest)
    prefix = sha1_hash[:5]   # sent to API
    suffix = sha1_hash[5:]   # kept locally for comparison

    # Step 3: Query the API with only the prefix
    try:
        response = requests.get(
            HIBP_API_URL + prefix,
            timeout=5,
            headers={"User-Agent": "VaultX-PasswordManager"}
        )
        response.raise_for_status()

    except requests.exceptions.ConnectionError:
        return {
            "breached": False,
            "breach_count": 0,
            "safe": True,
            "message": "⚠ Could not connect to breach database — check your internet",
            "error": True
        }
    except requests.exceptions.Timeout:
        return {
            "breached": False,
            "breach_count": 0,
            "safe": True,
            "message": "⚠ Breach check timed out — try again",
            "error": True
        }
    except Exception as e:
        return {
            "breached": False,
            "breach_count": 0,
            "safe": True,
            "message": f"⚠ Breach check failed: {str(e)}",
            "error": True
        }

    # Step 4: Search the returned list for our suffix
    # Response format: "SUFFIX:COUNT\r\nSUFFIX:COUNT\r\n..."
    breach_count = 0
    for line in response.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2:
            returned_suffix, count = parts
            if returned_suffix.upper() == suffix:
                breach_count = int(count)
                break

    # Step 5: Build the result
    if breach_count > 0:
        if breach_count >= 100000:
            severity = "CRITICAL"
            advice   = "This password is extremely common. Change it immediately everywhere."
        elif breach_count >= 10000:
            severity = "HIGH"
            advice   = "This password appears very frequently in breaches. Change it now."
        elif breach_count >= 1000:
            severity = "MEDIUM"
            advice   = "This password has been seen in many breaches. Change it soon."
        else:
            severity = "LOW"
            advice   = "This password appeared in at least one breach. Consider changing it."

        return {
            "breached":     True,
            "breach_count": breach_count,
            "severity":     severity,
            "safe":         False,
            "message":      f"⚠ Found {breach_count:,} times in known breaches!",
            "advice":       advice,
            "error":        False
        }

    return {
        "breached":     False,
        "breach_count": 0,
        "severity":     "NONE",
        "safe":         True,
        "message":      "✓ Not found in any known breach",
        "advice":       "This password has not appeared in known breach databases.",
        "error":        False
    }


# ============================================================
# PART 2: BATCH CHECK — scan entire vault
# Checks all stored passwords at once
# ============================================================

def check_vault_for_breaches(db, username: str, private_key: bytes) -> dict:
    """
    Scans all vault entries for a user and checks each
    password against the breach database.

    Returns a summary with which entries are compromised.
    """
    from app.vault import get_vault_entries, get_vault_entry

    # Get all vault entries
    entries = get_vault_entries(db, username)

    if not entries:
        return {
            "success":          True,
            "total_checked":    0,
            "breached_count":   0,
            "safe_count":       0,
            "results":          [],
            "message":          "No passwords to check"
        }

    results = []
    breached_count = 0
    safe_count     = 0
    error_count    = 0

    for entry in entries:
        # Decrypt each entry to get the password
        decrypted = get_vault_entry(
            db, username, entry["id"], private_key
        )

        if not decrypted["success"]:
            continue

        password = decrypted.get("password", "")
        website  = decrypted.get("website",  "")

        if not password:
            continue

        # Check this password against breach database
        result = check_password_breach(password)

        entry_result = {
            "entry_id":     entry["id"],
            "website":      website,
            "breached":     result["breached"],
            "breach_count": result["breach_count"],
            "severity":     result.get("severity", "NONE"),
            "message":      result["message"],
            "advice":       result.get("advice", ""),
            "error":        result.get("error", False)
        }

        results.append(entry_result)

        if result.get("error"):
            error_count += 1
        elif result["breached"]:
            breached_count += 1
        else:
            safe_count += 1

    # Sort — breached entries first
    results.sort(key=lambda x: (not x["breached"], -x["breach_count"]))

    summary_message = (
        f"{breached_count} breached, {safe_count} safe"
        if not error_count
        else f"{breached_count} breached, {safe_count} safe, {error_count} errors"
    )

    return {
        "success":        True,
        "total_checked":  len(results),
        "breached_count": breached_count,
        "safe_count":     safe_count,
        "error_count":    error_count,
        "results":        results,
        "message":        summary_message
    }