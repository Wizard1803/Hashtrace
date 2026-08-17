import sys
import argparse
from analyzer import analyze, get_strength_label, get_crack_times, TIER_EXPLANATIONS
from checker import load_wordlist, is_in_wordlist, is_mutation_of_wordlist,check_hibpwn, is_keyboard_walk, is_date_pattern, is_leetspeak_of_wordlist, is_hybrid_mutation_leetspeak
from policy import load_policy, check_policy
from bulk import run_bulk_audit
from suggestions import load_eff_wordlist, generate_suggestions, format_suggestions_panel
from banner import print_banner
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()

def print_tier_explanations():
    render_items = []
    tier_list = list(TIER_EXPLANATIONS.items())
    for i, (tier, desc) in enumerate(tier_list):
        suffix = "\n" if i < len(tier_list) - 1 else ""
        render_items.append(f"[bold cyan]• {tier}:[/]\n  [white]{desc}[/]{suffix}")

    panel = Panel(
        Group(*render_items),
        title="[bold magenta]Threat-Model Tier Descriptions[/]",
        border_style="magenta",
        expand=False
    )
    console.print(panel)
    console.print()

def get_time_color(t_str):
    if "second" in t_str or "minute" in t_str or "hour" in t_str:
        return "bold red"
    elif "day" in t_str or "month" in t_str:
        return "yellow"
    elif "year" in t_str:
        return "bold green"
    return "white"

def print_results(analysis, in_wordlist, pwned_count, crack_times, policy_result=None, suggestions=None):
    # We map strength labels to colors for better visual feedback
    strength_colors = {
        "Very Weak (Known Password)": "bold red",
        "Very Weak": "bold red",
        "Weak": "red",
        "Medium": "yellow",
        "Strong": "green",
        "Very Strong": "bold green"
    }
    color = strength_colors.get(analysis['strength'], "white")
    
    # Build a list of renderables to pass into the Panel's Group
    render_items = []
    
    render_items.append(f"[cyan]Password:[/] {analysis['password']}")
    # Dim the raw metrics so the real security warnings stand out
    render_items.append(f"[dim]Length: {analysis['length']}[/]")
    render_items.append(f"[dim]Charset Size: {analysis['charset_size']}[/]")
    render_items.append(f"[dim]Entropy: {analysis['entropy']} bits[/]")
    render_items.append(f"[cyan]Strength:[/] [{color}]{analysis['strength']}[/{color}]")
    render_items.append("") # spacer
    
    if pwned_count > 0:
        render_items.append(f"[cyan]PAWNED:[/] [bold red]YES - SEEN {pwned_count} times in breaches[/]")
    else:
        render_items.append("[cyan]PAWNED:[/] [bold green]NO[/]")
        
    render_items.append(f"[cyan]In Wordlist:[/] {'[bold red]YES - Instantly CRACKABLE[/]' if in_wordlist else '[bold green]NO[/]'}")
    
    if policy_result:
        passed, failed_rules = policy_result
        if passed:
            render_items.append("[cyan]Policy Compliance:[/] [bold green]PASSED[/]")
        else:
            render_items.append("[cyan]Policy Compliance:[/] [bold red]FAILED[/]")
            for rule in failed_rules:
                render_items.append(f"  [bold red]x[/] {rule}")
    
    if len(analysis["weaknesses"]) != 0:
        render_items.append("\n[yellow]Detected Weaknesses:[/]")
        for issues in analysis["weaknesses"]:
            render_items.append(f"  [bold red]>[/] {issues}")
    else:
        render_items.append("\n[green]No structural weaknesses found.[/]")
    
    render_items.append("") # spacer
    
    if crack_times: 
        table = Table(title="Estimated Time to Crack", show_header=True, header_style="bold magenta")
        table.add_column("Threat Model", style="cyan", no_wrap=True)
        table.add_column("Time") # We will color rows dynamically
        
        for tier, time_str in crack_times.items():
            t_color = get_time_color(time_str)
            table.add_row(tier, f"[{t_color}]{time_str}[/{t_color}]")
        
        render_items.append(table)
    else:
        # Using the exact phrasing requested in PROJECT_FRAMEWORK.md
        render_items.append("[bold red]Already compromised — time-to-crack is irrelevant.[/]")
    
    # Wrap everything in a nice bordered panel
    results_panel = Panel(
        Group(*render_items),
        title="[bold blue]Target Analysis Report[/]",
        border_style="blue",
        expand=False
    )
    
    console.print()
    console.print(results_panel)

    if suggestions:
        sug_panel = format_suggestions_panel(suggestions)
        if sug_panel:
            console.print()
            console.print(sug_panel)
    console.print()


def main():
    parser = argparse.ArgumentParser(description="HashTrace - Offensive Security Password Intelligence Tool")
    parser.add_argument("--bulk", nargs=2, metavar=("INPUT_TXT", "OUTPUT_CSV"), help="Audit multiple passwords from a .txt file and write results to .csv")
    args = parser.parse_args()

    active_policy = load_policy("policy.json")

    # If --bulk flag is provided, run bulk audit mode directly
    if args.bulk:
        input_file, output_file = args.bulk
        with console.status("[bold cyan]Loading wordlist...[/]"):
            wordlist = load_wordlist("Wordlists/rockyou.txt")
        run_bulk_audit(input_file, output_file, wordlist, active_policy, console=console)
        return

    print_banner(console)
    print_tier_explanations()
    
    eff_wordlist = load_eff_wordlist("Wordlists/eff_large_wordlist.txt")

    # UX Improvement: Status spinner while doing the heavy wordlist loading
    with console.status("[bold cyan]Loading wordlist...[/]"):
        wordlist = load_wordlist("Wordlists/rockyou.txt")         #it is a function made in checker.py, it's not built-in, keep it in mind
    console.print(f"[dim]Loaded {len(wordlist)} words from the wordlist[/]\n")

    while True:                                                 #important loop, combines almost all functions, logic is important
        # Replaced standard input() with Prompt.ask() to fix terminal overlap glitches
        password = Prompt.ask("\n[bold cyan]Enter a password to analyze (or type 'quit')[/]")
        if password.lower() == "quit":
            break
        if password == "":
            continue
        
        # UX Improvement: Another spinner while hitting HIBP API and checking rules
        with console.status("[bold cyan]Analyzing password...[/]"):
            analysis = analyze(password)
            in_wordlist = is_in_wordlist(password, wordlist)
            pwned_count = check_hibpwn(password)
            policy_result = check_policy(password, active_policy)
            crack_times = None
            keyboard_walk = is_keyboard_walk(password)
            if keyboard_walk:
                analysis["weaknesses"].append("Keyboard walk detected")
            has_date = is_date_pattern(password)
            if has_date:
                analysis["weaknesses"].append("Date pattern detected")
            
            if in_wordlist == True:
                analysis["entropy"] = 0
                analysis["strength"] = "Very Weak (Known Password)"
            else:
                is_mutation = is_mutation_of_wordlist(password, wordlist)
                is_leet = is_leetspeak_of_wordlist(password, wordlist)
                is_hybrid = is_hybrid_mutation_leetspeak(password, wordlist)
                
                multiplier = 1
                
                # Using if/elif here because if it's a hybrid, it is also a mutation and a leetspeak.
                # We don't want to penalize them 3 separate times for the exact same base word.
                if is_hybrid:
                    analysis["weaknesses"].append("Hybrid (Mutation + Leetspeak) detected")
                    multiplier *= 0.1
                elif is_mutation:
                    #if password has any weakness or mutation then entropy should be decreased so it's strength decreases
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
                
                # HARD CAP: If it's just a lowercase string (no upper, no numbers, no symbols)
                # it should never be able to reach "Strong" tier just by being extremely long.
                has_no_upper = "No uppercase letters" in analysis["weaknesses"]
                has_no_numbers = "No numbers" in analysis["weaknesses"]
                has_no_special = "No special characters" in analysis["weaknesses"]
                
                if has_no_upper and has_no_numbers and has_no_special:
                    if analysis["entropy"] > 45:
                        analysis["entropy"] = 45.0
                        analysis["weaknesses"].append("Lowercase string — entropy artificially capped")
                analysis["strength"] = get_strength_label(analysis["entropy"])
                
                # If it's not breached in HIBP either, calculate the crack times
                # Note: We do this AFTER penalties are applied so the time reflects structural weaknesses!
                if pwned_count == 0 and not (is_mutation or is_leet or is_hybrid):
                    crack_times = get_crack_times(analysis["entropy"])
            
            # Only provide passphrase recommendations if the password has weaknesses,
            # is compromised/breached, or failed the security policy check.
            needs_improvement = (
                analysis["strength"] in ["Very Weak", "Very Weak (Known Password)", "Weak", "Medium"]
                or in_wordlist
                or pwned_count > 0
                or len(analysis["weaknesses"]) > 0
                or (policy_result and not policy_result[0])
            )
            suggestions = generate_suggestions(eff_wordlist) if needs_improvement else None
            
        print_results(analysis, in_wordlist, pwned_count, crack_times, policy_result, suggestions)
        print() # Spacer before next input prompt

if __name__ == "__main__":
    main()

#Functions
#print_results()
#main()