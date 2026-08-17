import csv
import os
from analyzer import analyze, get_strength_label
from checker import is_in_wordlist, is_mutation_of_wordlist, is_leetspeak_of_wordlist, is_hybrid_mutation_leetspeak, is_keyboard_walk, is_date_pattern, check_hibpwn
from policy import check_policy

def detect_format(first_line):
    """
    Auto-detect whether the file format is:
    - 'user_pass': username,password format (contains at least one comma)
    - 'bare': bare password format (no comma)
    
    Returns: 'user_pass' or 'bare'
    """
    cleaned = first_line.strip()
    if "," in cleaned:
        return "user_pass"
    return "bare"


def parse_line(line, expected_format, line_number):
    """
    Parses a single line based on the expected_format.
    
    Returns: (identifier, password)
    Raises: ValueError if the line does not match the expected format.
    """
    cleaned = line.strip()
    if not cleaned:
        return None

    if expected_format == "user_pass":
        if "," not in cleaned:
            raise ValueError("Expected 'username,password' format, but found no comma.")
        parts = cleaned.split(",", 1)
        username = parts[0].strip()
        password = parts[1].strip()
        if not username:
            username = f"Line_{line_number}"
        return username, password
    else:
        # Bare password format
        return f"Line_{line_number}", cleaned


def run_bulk_audit(input_path, output_path, wordlist, policy, console=None):
    """
    Reads input .txt, processes passwords through HashTrace analysis,
    and writes results to output .csv without exposing raw passwords.
    """
    if not os.path.exists(input_path):
        if console:
            console.print(f"[bold red]Error:[/] Input file '{input_path}' not found.")
        else:
            print(f"Error: Input file '{input_path}' not found.")
        return False

    processed_count = 0
    skipped_count = 0
    expected_format = None

    fieldnames = [
        "Identifier",
        "Length",
        "Charset_Size",
        "Entropy",
        "Strength",
        "In_Wordlist",
        "Breached_Count",
        "Policy_Passed",
        "Weaknesses"
    ]

    try:
        with open(input_path, "r", encoding="utf-8", errors="ignore") as infile, \
             open(output_path, "w", encoding="utf-8", newline="") as outfile:
            
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()

            for line_num, raw_line in enumerate(infile, start=1):
                if not raw_line.strip():
                    continue

                # Auto-detect format on first non-empty line
                if expected_format is None:
                    expected_format = detect_format(raw_line)
                    if console:
                        console.print(f"[dim]Auto-detected input format: '{expected_format}'[/]")

                try:
                    parsed = parse_line(raw_line, expected_format, line_num)
                    if parsed is None:
                        continue
                    identifier, password = parsed
                except ValueError as e:
                    skipped_count += 1
                    if console:
                        console.print(f"[yellow]Line {line_num} skipped: {e}[/]")
                    continue

                # Run full analysis
                analysis = analyze(password)
                in_dict = is_in_wordlist(password, wordlist)
                pwned_count = check_hibpwn(password)
                
                # Weaknesses detection
                if is_keyboard_walk(password):
                    analysis["weaknesses"].append("Keyboard walk detected")
                if is_date_pattern(password):
                    analysis["weaknesses"].append("Date pattern detected")

                # Entropy adjustments
                if in_dict:
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
                        analysis["weaknesses"].append("Mutation of known password detected")
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

                    # Lowercase hard cap
                    has_no_upper = "No uppercase letters" in analysis["weaknesses"]
                    has_no_numbers = "No numbers" in analysis["weaknesses"]
                    has_no_special = "No special characters" in analysis["weaknesses"]
                    if has_no_upper and has_no_numbers and has_no_special and analysis["entropy"] > 45:
                        analysis["entropy"] = 45.0
                        analysis["weaknesses"].append("Lowercase string - entropy artificially capped")

                    analysis["strength"] = get_strength_label(analysis["entropy"])

                # Policy check
                policy_passed, _ = check_policy(password, policy)

                # Write to CSV (raw password is intentionally EXCLUDED)
                writer.writerow({
                    "Identifier": identifier,
                    "Length": analysis["length"],
                    "Charset_Size": analysis["charset_size"],
                    "Entropy": analysis["entropy"],
                    "Strength": analysis["strength"],
                    "In_Wordlist": "YES" if in_dict else "NO",
                    "Breached_Count": pwned_count,
                    "Policy_Passed": "YES" if policy_passed else "NO",
                    "Weaknesses": " | ".join(analysis["weaknesses"]) if analysis["weaknesses"] else "None"
                })

                processed_count += 1

        if console:
            console.print(f"\n[bold green]Bulk audit complete![/]")
            console.print(f"Processed: [cyan]{processed_count}[/] accounts | Skipped: [yellow]{skipped_count}[/] lines")
            console.print(f"Output saved to: [bold underline]{output_path}[/]\n")
        return True

    except Exception as e:
        if console:
            console.print(f"[bold red]Error during bulk processing:[/] {e}")
        else:
            print(f"Error during bulk processing: {e}")
        return False
