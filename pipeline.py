import time
from analyzer import analyze, get_strength_label, get_crack_times
from checker import (
    is_in_wordlist, is_mutation_of_wordlist, is_leetspeak_of_wordlist, 
    is_hybrid_mutation_leetspeak, is_keyboard_walk, is_date_pattern, check_hibpwn
)
from policy import check_policy

def run_full_analysis(password, wordlist, policy, skip_hibp=False, throttle_hibp=False):
    # run analysis, check HIBP/wordlists, apply penalties, and verify policy
    analysis = analyze(password)
    in_wordlist = is_in_wordlist(password, wordlist)
    
    if skip_hibp:
        pwned_count = -1
    else:
        if throttle_hibp:
            time.sleep(1.6) # HIBP rate limit is ~1 req per 1.5s
        pwned_count = check_hibpwn(password)
        
    policy_result = check_policy(password, policy)
    
    if is_keyboard_walk(password):
        analysis["weaknesses"].append("Keyboard walk detected")
    if is_date_pattern(password):
        analysis["weaknesses"].append("Date pattern detected")
        
    is_mutation = False
    is_leet = False
    is_hybrid = False
        
    if in_wordlist:
        analysis["entropy"] = 0.0
        analysis["strength"] = "Very Weak (Known Password)"
    else:
        is_mutation = is_mutation_of_wordlist(password, wordlist)
        is_leet = is_leetspeak_of_wordlist(password, wordlist)
        is_hybrid = is_hybrid_mutation_leetspeak(password, wordlist)
        
        multiplier = 1.0
        
        if is_hybrid:
            analysis["weaknesses"].append("Hybrid (Mutation + Leetspeak) detected")
            multiplier *= 0.1
        elif is_mutation:
            analysis["weaknesses"].append("Mutation of known password is Detected")
            multiplier *= 0.2
        elif is_leet:
            analysis["weaknesses"].append("Leet-speak pattern detected")
            multiplier *= 0.2
            
        if "Repeating characters Detected" in analysis["weaknesses"]:
            multiplier *= 0.3
        if "Keyboard walk detected" in analysis["weaknesses"]:
            multiplier *= 0.1
        if "Date pattern detected" in analysis["weaknesses"]:
            multiplier *= 0.5
            
        analysis["entropy"] = round(analysis["entropy"] * multiplier, 2)
        
        # HARD CAP: Lowercase string only
        has_no_upper = "No uppercase letters" in analysis["weaknesses"]
        has_no_numbers = "No numbers" in analysis["weaknesses"]
        has_no_special = "No special characters" in analysis["weaknesses"]
        
        if has_no_upper and has_no_numbers and has_no_special:
            if analysis["entropy"] > 45:
                analysis["entropy"] = 45.0
                analysis["weaknesses"].append("Lowercase string — entropy artificially capped")
                
        analysis["strength"] = get_strength_label(analysis["entropy"])
        
    crack_times = None
    # Calculate crack times only if not breached and not based on a dictionary word
    if pwned_count == 0 and not (in_wordlist or is_mutation or is_leet or is_hybrid):
        crack_times = get_crack_times(analysis["entropy"])
        
    return analysis, in_wordlist, pwned_count, policy_result, crack_times
