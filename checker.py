import re
import hashlib
import requests

def load_wordlist(wordlist_path):
    try:
        with open(wordlist_path, 'r', encoding = 'UTF-8', errors ='ignore') as file:
            wordlist = {line.strip().lower() for line in file}
            return wordlist
    except FileNotFoundError:
        print(f"Error: Wordlist file not found at {wordlist_path}")
        return set()

def is_mutation_of_wordlist(password, wordlist):
    base = re.sub(r'^[^a-zA-Z]+|[^a-zA-Z]+$', '', password)
    base = base.lower()

    if base == "" or base == password.lower():
        return False 
    return base.lower() in wordlist

# pre-compute bad 4-key walk sequences from a standard QWERTY keyboard
KEYBOARD_ROWS = [
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm"
]
WALK_CHUNKS = set()
for row in KEYBOARD_ROWS:
    for i in range(len(row) - 3):
        chunk = row[i:i+4]
        WALK_CHUNKS.add(chunk)          
        WALK_CHUNKS.add(chunk[::-1])    

def is_keyboard_walk(password):
    for chunks in WALK_CHUNKS:
        if chunks in password.lower():
            return True
    return False

def is_date_pattern(password):
    # Detect 4-digit years in the password (e.g., 1900 to 2030) at the start or end only.
    return bool(re.search(r'^(19[0-9]{2}|20[0-2][0-9]|2030)|(19[0-9]{2}|20[0-2][0-9]|2030)$', password))

LEET_MAPPING = {
    '@': 'a',
    '4': 'a',
    '0': 'o',
    '3': 'e',
    '1': 'i',
    '!': 'i',
    '$': 's',
    '5': 's',
    '7': 't',
    '8': 'b',
    '+': 't'
}

def is_leetspeak_of_wordlist(password, wordlist):
    # Normalize leetspeak and check against wordlist
    normalized = password.lower()
    for leet_char, normal_char in LEET_MAPPING.items():
        normalized = normalized.replace(leet_char, normal_char)
        
    # If the password didn't change at all, it wasn't leetspeak
    if normalized == password.lower():
        return False
        
    return normalized in wordlist

def is_hybrid_mutation_leetspeak(password, wordlist):
    # Step 1: Strip padding from the edges (Mutation phase)
    base = re.sub(r'^[^a-zA-Z]+|[^a-zA-Z]+$', '', password)
    if base == "" or base == password:
        return False
        
    # Step 2: Normalize the remaining core word (Leetspeak phase)
    normalized = base.lower()
    for leet_char, normal_char in LEET_MAPPING.items():
        normalized = normalized.replace(leet_char, normal_char)
        
    if normalized == base.lower():
        return False  # It was just a normal mutation, no leetspeak involved
        
    # Step 3: Check if the stripped + normalized word is in the wordlist
    return normalized in wordlist

def is_in_wordlist(password, wordlist):
    return password.lower() in wordlist




# k-anonymity trick: only send the first 5 chars of the sha1 hash to the API. 
# we check the rest of the hash locally so we don't leak the password over the network.
def check_hibpwn(password):
    hash = hashlib.sha1(password.encode()).hexdigest().upper()

    first5 = hash[:5]
    suffix = hash[5:]

    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{first5}", timeout=5)
        response.raise_for_status()
    except requests.RequestException:
        # Return -1 to indicate the API check failed/was skipped due to network error
        return -1

    for line in response.text.splitlines():
        returned_suffix, count = line.split(":")
        if returned_suffix == suffix:
            return int(count)
    return 0