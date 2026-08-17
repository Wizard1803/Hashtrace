import re
import math

def get_charset_size(password):

    counter = 0

    if re.search(r'[a-z]', password):
        counter += 26
    if re.search(r'[A-Z]', password):
        counter += 26
    if re.search(r'[0-9]', password):
        counter += 10
    if re.search(r'[-!@#$%^&*()_+={}[\]\\;:,.<>?]', password):
        counter += 32

    return counter


def calculate_entropy(password):
    size = get_charset_size(password)

    if size == 0 :
        return 0
    else:
        return round(math.log2(size) * len(password), 2)


def get_strength_label(entropy):
    if entropy < 29:
        return "Very Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        return "Medium"
    elif entropy < 128:
        return "Strong"
    else:
        return "Very Strong"

#function to check for common strong password practices 
def get_weaknesses(password):
    issues = []

    if len(password) < 8:
        issues.append("Too short — minimum 8 characters")
    if not re.search(r'[A-Z]', password):         #used regular expression here for character checking in password
        issues.append("No uppercase letters")
    if not re.search(r'[0-9]', password):
        issues.append("No numbers")
    if not re.search(r'[-!@#$%^&*()_+={}[\]\\;:,.<>?]', password):
        issues.append("No special characters")
    if re.search(r'(.)\1{2,}', password):
        issues.append("Repeating characters Detected")

    return issues

def format_seconds_to_readable(seconds):
    # Core Logic: Convert raw seconds into a readable string (years, days, hours, minutes, seconds).
    # - Decreasing order unit selection.
    # - Max 100 years. If > 100 years, show label + scientific notation (e.g., ">100 Years (3.5e+15 seconds)").
    # - Hours get 1 decimal place; all other units round to nearest whole number.
    minute = 60
    hour = minute * 60
    day = hour * 24
    month = day * 30
    year = day * 365
    if seconds >= 100 * year:
        return f"> 100 years ({seconds / year:.1e} years)"
    elif seconds >= year:
        return f"{seconds / year:.0f} year"
    elif seconds >= month:
        return f"{seconds / month:.0f} months"
    elif seconds >= day:
        return f"{seconds / day:.0f} days"
    elif seconds >= hour:
        return f"{seconds / hour:.1f} hours"
    elif seconds >= minute:
        return f"{seconds / minute:.0f} minutes"
    else:
        return f"{seconds:.0f} seconds"

def get_crack_times(entropy):
    # Core Logic: Calculate time-to-crack across 4 threat-model tiers.
    # Formula: seconds = (2 ** entropy) / rate
    # Returns a dictionary mapping the tier name to the readable time string.
    tiers = {
        "Online Attack (Throttled)": 10,
        "Offline Attack (Slow Hash)": 10000,
        "Offline Attack (Fast Hash)": 10000000000,
        "Massive GPU Cluster": 1000000000000
    }
    crack_times = {}
    for tier, rate in tiers.items():
        crack_times[tier] = format_seconds_to_readable((2 ** entropy) / rate)
    return crack_times

def analyze(password):
    entropy = calculate_entropy(password)
    analysis = {
        "password" : password,
        "length" : len(password),
        "charset_size" : get_charset_size(password),
        "entropy" : entropy,
        "strength" : get_strength_label(entropy),
        "weaknesses" : get_weaknesses(password)
    }
    return analysis

TIER_EXPLANATIONS = {
    "Online Attack (Throttled)": "When the password is sprayed against a live login form. The system allows 10 guesses per second.",
    "Offline Attack (Slow Hash)":  "When the attacker has a database dump and is using a slow hashing algorithm like bcrypt (10,000 guesses per second).",
    "Offline Attack (Fast Hash)" :"When the attacker has a database dump and is using a fast hashing algorithm like MD5 or SHA-1 (10 Billion guesses per second).",
    "Massive GPU Cluster" :  "When the attacker has unlimited resources (e.g., a nation-state or cartel) using thousands of high-end GPUs (100 Trillion guesses per second)."
}

#Functions
#get_charset_size()
#calculate_entropy()
#get_strength_label()
#get_weaknesses()
#analyze()