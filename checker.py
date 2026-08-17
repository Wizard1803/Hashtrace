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

# KEYBOARD WALKS
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
    # Detect 4-digit years in the password (e.g., 1900 to 2030).
    return bool(re.search(r'(19[0-9]{2}|20[0-2][0-9]|2030)', password))

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




# Here in this function the user password is converted into hash using sha1
# then broken into first5 and remaining suffix (it is because we shouldn't
# check or search for whole hash through api, it may leak from api attacks)

# then first5 of hashed value is passed through hibpwned api and gets all the hash values 
# of the matching hashes and stores in response
# then response is checked and matched with the suffix of user password
#  this is how the function checks compromised passwords from haveibeenpwned passwords
def check_hibpwn(password):
    hash = hashlib.sha1(password.encode()).hexdigest().upper()

    first5 = hash[:5]
    suffix = hash[5:]

    response = requests.get(f"https://api.pwnedpasswords.com/range/{first5}")

    for line in response.text.splitlines():
        returned_suffix, count = line.split(":")
        if returned_suffix == suffix:
            return int(count)
    return 0