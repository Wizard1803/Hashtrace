import csv
import os
import time
from pipeline import run_full_analysis

def detect_format(first_line):
    # auto-detect if format is 'user_pass' or 'bare'
    cleaned = first_line.strip()
    if "," in cleaned:
        return "user_pass"
    return "bare"


def parse_line(line, expected_format, line_number):

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


def run_bulk_audit(input_path, output_path, wordlist, policy, skip_hibp=False, console=None):
    # run bulk analysis and write to CSV (excluding raw passwords)
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
                analysis, in_dict, pwned_count, policy_result, _ = run_full_analysis(
                    password, wordlist, policy, skip_hibp=skip_hibp, throttle_hibp=True
                )

                # Policy check
                policy_passed = policy_result[0] if policy_result else False

                # Write to CSV (raw password is intentionally EXCLUDED)
                writer.writerow({
                    "Identifier": identifier,
                    "Length": analysis["length"],
                    "Charset_Size": analysis["charset_size"],
                    "Entropy": analysis["entropy"],
                    "Strength": analysis["strength"],
                    "In_Wordlist": "YES" if in_dict else "NO",
                    "Breached_Count": "SKIPPED" if pwned_count == -1 else pwned_count,
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
