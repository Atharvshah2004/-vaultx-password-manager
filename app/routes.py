from app.breach import check_password_breach, check_vault_for_breaches
from flask import redirect
from flask import Blueprint, request, jsonify, session
from app.auth import register_user, login_user
from app.vault import (
    add_vault_entry, get_vault_entries,
    get_vault_entry, update_vault_entry,
    delete_vault_entry
)
from app.password_gen import generate_password, analyze_password_strength
from app.honey import check_honey_access, get_security_alerts, create_honey_entry

main_bp = Blueprint("main", __name__)

# ============================================================
# HELPER: Check if user is logged in
# ============================================================

def get_logged_in_user():
    """
    Returns the username if logged in, None if not.
    Also returns the private key stored in session.
    """
    username = session.get("username")
    private_key_b64 = session.get("private_key")
    public_key_str = session.get("public_key")

    if not username or not private_key_b64:
        return None, None, None

    import base64
    private_key = base64.b64decode(private_key_b64)
    public_key = public_key_str.encode() if public_key_str else None

    return username, private_key, public_key


# ============================================================
# ROUTE 1: HOME
# ============================================================

@main_bp.route("/")
def index():
    from flask import render_template
    return render_template("index.html")

@main_bp.route("/dashboard")
def dashboard():
    from flask import render_template
    if not session.get("username"):
        return redirect("/")
    return render_template("dashboard.html")
# ============================================================
# ROUTE 2: REGISTER
# ============================================================

@main_bp.route("/register", methods=["POST"])
def register():
    from flask import current_app
    data = request.get_json()

    # Validate input
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"success": False, "message": "Username and password required"}), 400

    username = data["username"].strip()
    password = data["password"]

    # Check password strength before registering
    strength = analyze_password_strength(password)
    if strength["score"] < 4:
        return jsonify({
            "success": False,
            "message": f"Master password too weak: {strength['feedback'][0]}"
        }), 400

    db = current_app.db
    result = register_user(db, username, password)

    if result["success"]:
        return jsonify(result), 201
    return jsonify(result), 409


# ============================================================
# ROUTE 3: LOGIN
# ============================================================

@main_bp.route("/login", methods=["POST"])
def login():
    from flask import current_app
    import base64

    data = request.get_json()
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"success": False, "message": "Username and password required"}), 400

    db = current_app.db
    result = login_user(db, data["username"].strip(), data["password"])

    if result["success"]:
        session["username"] = result["username"]
        session["private_key"] = base64.b64encode(result["private_key"]).decode()
        session["public_key"] = result["public_key"].decode()
        return jsonify({
            "success": True,
            "message": result["message"],
            "username": result["username"]
        })

    # ── Pass exact message + locked flag to frontend ──
    return jsonify({
        "success": False,
        "message": result["message"],
        "locked": result.get("locked", False),
        "attempts_left": result.get("attempts_left", None)
    }), 423 if result.get("locked") else 401

# ============================================================
# ROUTE 4: LOGOUT
# ============================================================

@main_bp.route("/logout", methods=["POST"])
def logout():
    # Clear all session data
    session.clear()
    return jsonify({"success": True, "message": "Logged out successfully"})


# ============================================================
# ROUTE 5: GET VAULT LIST
# ============================================================

@main_bp.route("/vault", methods=["GET"])
def vault_list():
    from flask import current_app

    username, private_key, public_key = get_logged_in_user()
    if not username:
        return jsonify({"success": False, "message": "Not logged in"}), 401

    db = current_app.db
    entries = get_vault_entries(db, username)
    return jsonify({"success": True, "entries": entries})


# ============================================================
# ROUTE 6: ADD VAULT ENTRY
# ============================================================

@main_bp.route("/vault/add", methods=["POST"])
def vault_add():
    from flask import current_app

    username, private_key, public_key = get_logged_in_user()
    if not username:
        return jsonify({"success": False, "message": "Not logged in"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "No data provided"}), 400

    db = current_app.db
    result = add_vault_entry(db, username, public_key, data)

    if result["success"]:
        return jsonify(result), 201
    return jsonify(result), 400


# ============================================================
# ROUTE 7: GET ONE VAULT ENTRY (DECRYPTED)
# ============================================================

@main_bp.route("/vault/get", methods=["POST"])
def vault_get():
    from flask import current_app

    username, private_key, public_key = get_logged_in_user()
    if not username:
        return jsonify({"success": False, "message": "Not logged in"}), 401

    data = request.get_json()
    if not data or not data.get("entry_id"):
        return jsonify({"success": False, "message": "Entry ID required"}), 400

    entry_id = data["entry_id"]
    db = current_app.db

    # Check if this is a honey entry
    if check_honey_access(db, username, entry_id):
        # Return a special flag so the frontend can show the alert
        return jsonify({
            "success": False,
            "honey_triggered": True,
            "message": "Entry not found"
        }), 404

    result = get_vault_entry(db, username, entry_id, private_key)
    if result["success"]:
        return jsonify(result)
    return jsonify(result), 404


# ============================================================
# ROUTE 8: UPDATE VAULT ENTRY
# ============================================================

@main_bp.route("/vault/update", methods=["POST"])
def vault_update():
    from flask import current_app

    username, private_key, public_key = get_logged_in_user()
    if not username:
        return jsonify({"success": False, "message": "Not logged in"}), 401

    data = request.get_json()
    if not data or not data.get("entry_id"):
        return jsonify({"success": False, "message": "Entry ID required"}), 400

    entry_id = data.pop("entry_id")
    db = current_app.db
    result = update_vault_entry(db, username, entry_id, public_key, data)

    if result["success"]:
        return jsonify(result)
    return jsonify(result), 404


# ============================================================
# ROUTE 9: DELETE VAULT ENTRY
# ============================================================

@main_bp.route("/vault/delete", methods=["POST"])
def vault_delete():
    from flask import current_app

    username, private_key, public_key = get_logged_in_user()
    if not username:
        return jsonify({"success": False, "message": "Not logged in"}), 401

    data = request.get_json()
    if not data or not data.get("entry_id"):
        return jsonify({"success": False, "message": "Entry ID required"}), 400

    db = current_app.db
    result = delete_vault_entry(db, username, data["entry_id"])

    if result["success"]:
        return jsonify(result)
    return jsonify(result), 404


# ============================================================
# ROUTE 10: GENERATE PASSWORD
# ============================================================

@main_bp.route("/generate", methods=["POST"])
def generate():
    data = request.get_json() or {}

    # Get options from request or use defaults
    length          = int(data.get("length", 16))
    use_uppercase   = data.get("use_uppercase", True)
    use_lowercase   = data.get("use_lowercase", True)
    use_digits      = data.get("use_digits", True)
    use_symbols     = data.get("use_symbols", True)
    exclude_ambiguous = data.get("exclude_ambiguous", False)

    # Enforce safe length range
    length = max(8, min(64, length))

    password = generate_password(
        length=length,
        use_uppercase=use_uppercase,
        use_lowercase=use_lowercase,
        use_digits=use_digits,
        use_symbols=use_symbols,
        exclude_ambiguous=exclude_ambiguous
    )

    strength = analyze_password_strength(password)

    return jsonify({
        "success": True,
        "password": password,
        "strength": strength
    })


# ============================================================
# ROUTE 11: ANALYZE PASSWORD STRENGTH
# ============================================================

@main_bp.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    if not data or not data.get("password"):
        return jsonify({"success": False, "message": "Password required"}), 400

    result = analyze_password_strength(data["password"])
    return jsonify({"success": True, "analysis": result})


# ============================================================
# ROUTE 12: GET SECURITY ALERTS
# ============================================================

@main_bp.route("/alerts", methods=["GET"])
def alerts():
    from flask import current_app

    username, _, _ = get_logged_in_user()
    if not username:
        return jsonify({"success": False, "message": "Not logged in"}), 401

    db = current_app.db
    alert_list = get_security_alerts(db, username)
    return jsonify({"success": True, "alerts": alert_list})

# ============================================================
# ROUTE 13: CHECK SINGLE PASSWORD FOR BREACHES
# ============================================================

@main_bp.route("/breach/check", methods=["POST"])
def breach_check():
    data = request.get_json()
    if not data or not data.get("password"):
        return jsonify({"success": False, "message": "Password required"}), 400

    result = check_password_breach(data["password"])
    return jsonify({"success": True, "result": result})


# ============================================================
# ROUTE 14: SCAN ENTIRE VAULT FOR BREACHES
# ============================================================

@main_bp.route("/breach/scan", methods=["POST"])
def breach_scan():
    from flask import current_app

    username, private_key, public_key = get_logged_in_user()
    if not username:
        return jsonify({"success": False, "message": "Not logged in"}), 401

    db = current_app.db
    result = check_vault_for_breaches(db, username, private_key)
    return jsonify(result)