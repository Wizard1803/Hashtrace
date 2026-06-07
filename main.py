from analyzer import analyze, get_strength_label
from checker import load_wordlist, is_in_wordlist, is_mutation_of_wordlist,check_hibpwn

def print_results(analysis, in_wordlist, pwned_count):
    print("=" * 40)
    print(f"Password: {analysis['password']}")
    print(f"Length: {analysis['length']}")
    print(f"Charset Size: {analysis['charset_size']}")
    print(f"Entropy: {analysis['entropy']}")
    print(f"Strength: {analysis['strength']}")
    if pwned_count > 0 :
        print(f"PAWNED : YES - SEEN {pwned_count} times in breaches")
    else:
            print("PAWNED : NO")
    print(f"In Wordlist: {'YES - Instantly CRACKABLE' if in_wordlist else 'NO'}")
    if len(analysis["weaknesses"])!=0:
        for issues in analysis["weaknesses"]:
            print(issues)
    else:
        print("no issues found")
    print("=" * 40)


def main():
    print("Welcome to the Password Analyzer")
    wordlist = load_wordlist("Wordlists/rockyou.txt")         #it is a function made in checker.py, it's not built-in, keep it in mind
    print(f"Loaded {len(wordlist)} words from the wordlist")

    while True:                                                 #important loop, combines almost all funtions, logic is important
        password = input("Enter a password to analyze: ")
        if password == "quit":
            break
        if password == "":
            continue
        analysis = analyze(password)
        in_wordlist = is_in_wordlist(password, wordlist)
        pwned_count = check_hibpwn(password)

        if in_wordlist==True:
            analysis["entropy"] = 0
            analysis["strength"] = "Very Weak (Known Password)"
        else:
            is_mutation = is_mutation_of_wordlist(password, wordlist)
            if is_mutation == True:
                #if password has any weakness or mutation then entropy should be decreased so it's strength decreases
                analysis["weaknesses"].append("Mutation of known password is Detected")
                analysis["entropy"] = round(analysis["entropy"] * 0.6, 2)
                analysis["strength"] = get_strength_label(analysis["entropy"])
            if "Repeating characters Detected" in analysis["weaknesses"]:
                analysis["entropy"] = round(analysis["entropy"] * 0.7, 2)
                analysis["strength"] = get_strength_label(analysis["entropy"])

            

        print_results(analysis, in_wordlist, pwned_count)

if __name__ == "__main__":
    main()

#Functions
#print_results()
#main()