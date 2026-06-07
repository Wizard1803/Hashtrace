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
    base = re.sub(r'^[0-9!@#]+|[0-9!@#]+$', '', password)

    base = base.lower()

    if base == "" or base == password.lower():
        return False 
    return base.lower() in wordlist

def is_in_wordlist(password, wordlist):
    return password.lower() in wordlist




# Here in this function the user password is converted into hash using sha1
# then broken into first5 and remaining suffix (it is because we shouldn't
# check or search for whole hash through api, it may leak or 
# we can say hibpwn knows someone password and it's 'almost' leaked now)

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

#Functions:
#load_wordlist()
#is_mutation_of_wordlist()
#is_in_wordlist()
#check_hibpwn()