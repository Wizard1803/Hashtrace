import json
import re
import os

DEFAULT_POLICY = {
    "min_length": 12,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_numbers": True,
    "require_symbols": True
}

def validate_policy_config(raw_config):
    # validate each field individually and fallback to defaults for invalid fields
    if not isinstance(raw_config, dict):
        print("[!] Policy config must be a JSON object/dict. Using default policy.")
        return DEFAULT_POLICY.copy()

    validated = {}
    
    # 1. Validate min_length (must be an integer > 0, note: bool is subclass of int in Python)
    min_len = raw_config.get("min_length")
    if isinstance(min_len, int) and not isinstance(min_len, bool) and min_len > 0:
        validated["min_length"] = min_len
    else:
        validated["min_length"] = DEFAULT_POLICY["min_length"]

    # 2. Validate boolean flags
    bool_flags = ["require_uppercase", "require_lowercase", "require_numbers", "require_symbols"]
    for flag in bool_flags:
        val = raw_config.get(flag)
        if isinstance(val, bool):
            validated[flag] = val
        else:
            validated[flag] = DEFAULT_POLICY[flag]

    return validated


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_POLICY_PATH = os.path.join(BASE_DIR, "policy.json")

def load_policy(filepath=DEFAULT_POLICY_PATH):

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            raw_config = json.load(f)
            return validate_policy_config(raw_config)
    except FileNotFoundError:
        print(f"[!] Policy file '{filepath}' not found. Using default policy.")
        return DEFAULT_POLICY.copy()
    except json.JSONDecodeError:
        print(f"[!] Policy file '{filepath}' contains invalid JSON. Using default policy.")
        return DEFAULT_POLICY.copy()


def check_policy(password, policy):

    failed_rules = []

    # 1. Check minimum length
    min_length = policy.get("min_length", DEFAULT_POLICY["min_length"])
    if len(password) < min_length:
        failed_rules.append(f"Too short - minimum required length is {min_length} (current: {len(password)})")

    # 2. Check uppercase letter
    if policy.get("require_uppercase", DEFAULT_POLICY["require_uppercase"]):
        if not re.search(r'[A-Z]', password):
            failed_rules.append("No uppercase letters")

    # 3. Check lowercase letter
    if policy.get("require_lowercase", DEFAULT_POLICY["require_lowercase"]):
        if not re.search(r'[a-z]', password):
            failed_rules.append("No lowercase letters")

    # 4. Check numbers
    if policy.get("require_numbers", DEFAULT_POLICY["require_numbers"]):
        if not re.search(r'[0-9]', password):
            failed_rules.append("No numbers")

    # 5. Check symbols / special characters
    if policy.get("require_symbols", DEFAULT_POLICY["require_symbols"]):
        if not re.search(r'[-!@#$%^&*()_+={}[\]\\;:,.<>?]', password):
            failed_rules.append("No special characters")

    passed = len(failed_rules) == 0
    return passed, failed_rules
