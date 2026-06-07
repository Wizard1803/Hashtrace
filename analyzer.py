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

#Functions
#get_charset_size()
#calculate_entropy()
#get_strength_label()
#get_weaknesses()
#analyze()