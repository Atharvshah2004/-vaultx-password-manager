import os
import string
import math

# ============================================================
# PART 1: PASSWORD GENERATOR
# Uses os.urandom() for cryptographically secure randomness.
# NEVER use random.random() or random.choice() for passwords!
# ============================================================

def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False
) -> str:
    """
    Generates a cryptographically secure random password.

    Parameters:
    - length          : how long the password should be (min 8)
    - use_uppercase   : include A-Z
    - use_lowercase   : include a-z
    - use_digits      : include 0-9
    - use_symbols     : include !@#$%^&*
    - exclude_ambiguous: exclude confusing chars like 0,O,l,1,I
    """

    # Step 1: Enforce minimum length
    if length < 8:
        length = 8

    # Step 2: Build the character pool based on options
    character_pool = ""

    if use_uppercase:
        character_pool += string.ascii_uppercase        # A-Z

    if use_lowercase:
        character_pool += string.ascii_lowercase        # a-z

    if use_digits:
        character_pool += string.digits                 # 0-9

    if use_symbols:
        character_pool += "!@#$%^&*()-_=+[]{}|;:,.<>?" # symbols

    # Step 3: Remove ambiguous characters if requested
    if exclude_ambiguous:
        ambiguous = "0O1lI|`\'"
        character_pool = "".join(c for c in character_pool if c not in ambiguous)

    # Step 4: Make sure we have characters to work with
    if not character_pool:
        raise ValueError("At least one character type must be selected!")

    # Step 5: Use os.urandom() for secure random selection
    # We generate random indices into our character pool
    password_chars = []
    pool_size = len(character_pool)

    for _ in range(length):
        # Get one random byte (0-255) and use modulo to pick a character
        random_index = ord(os.urandom(1)) % pool_size
        password_chars.append(character_pool[random_index])

    # Step 6: Guarantee at least one character from each selected type
    # This ensures the password always passes its own strength rules
    guaranteed = []

    if use_uppercase:
        guaranteed.append(character_pool[ord(os.urandom(1)) % len(string.ascii_uppercase)])
    if use_lowercase:
        guaranteed.append(character_pool[ord(os.urandom(1)) % len(string.ascii_lowercase)])
    if use_digits:
        guaranteed.append(string.digits[ord(os.urandom(1)) % len(string.digits)])
    if use_symbols:
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        guaranteed.append(symbols[ord(os.urandom(1)) % len(symbols)])

    # Replace first N characters with guaranteed ones
    for i, char in enumerate(guaranteed):
        if i < len(password_chars):
            password_chars[i] = char

    # Step 7: Shuffle the password so guaranteed chars aren't always at the start
    # We use Fisher-Yates shuffle with os.urandom()
    for i in range(len(password_chars) - 1, 0, -1):
        j = ord(os.urandom(1)) % (i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


# ============================================================
# PART 2: PASSWORD STRENGTH ANALYZER
# Checks entropy and character variety to score the password
# ============================================================

def analyze_password_strength(password: str) -> dict:
    """
    Analyzes how strong a password is.
    Returns a score, label, and detailed feedback.
    """

    score = 0
    feedback = []

    # Check 1: Length scoring
    length = len(password)
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1
    if length < 8:
        feedback.append("Too short — use at least 8 characters")

    # Check 2: Character variety
    has_upper   = any(c.isupper() for c in password)
    has_lower   = any(c.islower() for c in password)
    has_digit   = any(c.isdigit() for c in password)
    has_symbol  = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password)

    if has_upper:
        score += 1
    else:
        feedback.append("Add uppercase letters (A-Z)")

    if has_lower:
        score += 1
    else:
        feedback.append("Add lowercase letters (a-z)")

    if has_digit:
        score += 1
    else:
        feedback.append("Add numbers (0-9)")

    if has_symbol:
        score += 1
    else:
        feedback.append("Add symbols (!@#$...)")

    # Check 3: Calculate entropy (bits)
    # Entropy = length × log2(pool_size)
    # Higher entropy = harder to crack
    pool_size = 0
    if has_upper:   pool_size += 26
    if has_lower:   pool_size += 26
    if has_digit:   pool_size += 10
    if has_symbol:  pool_size += 32

    if pool_size > 0:
        entropy = length * math.log2(pool_size)
    else:
        entropy = 0

    if entropy >= 60:
        score += 1
    if entropy >= 80:
        score += 1

    # Check 4: Common password patterns (very basic check)
    common_patterns = ["123456", "password", "qwerty", "abc123", "111111"]
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 2
        feedback.append("Avoid common patterns like '123456' or 'password'")

    # Calculate final strength label
    if score >= 8:
        strength = "Very Strong"
        color = "green"
    elif score >= 6:
        strength = "Strong"
        color = "blue"
    elif score >= 4:
        strength = "Fair"
        color = "orange"
    else:
        strength = "Weak"
        color = "red"

    return {
        "score": score,
        "strength": strength,
        "color": color,
        "entropy_bits": round(entropy, 1),
        "length": length,
        "has_uppercase": has_upper,
        "has_lowercase": has_lower,
        "has_digits": has_digit,
        "has_symbols": has_symbol,
        "feedback": feedback if feedback else ["Looks good!"]
    }