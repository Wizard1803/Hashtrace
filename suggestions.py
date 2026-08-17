import os
import secrets
from analyzer import calculate_entropy, get_strength_label
from rich.console import Console, Group
from rich.panel import Panel

# Allowed random separators between passphrase words (numbers and symbols)
SEPARATORS = list("0123456789!@#$%^&*-_+=")

def load_eff_wordlist(filepath="Wordlists/eff_large_wordlist.txt"):
    """
    Scaffold (Agent):
    Loads words from the EFF wordlist file into a Python list.
    """
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip().lower() for line in f if line.strip()]
            return words
    except Exception:
        return []


def _join_words_with_separators(words):
    """Helper to join a list of words with randomly chosen separators."""
    parts = []
    for i, w in enumerate(words):
        parts.append(w)
        if i < len(words) - 1:
            parts.append(secrets.choice(SEPARATORS))
    return "".join(parts)


def generate_suggestions(wordlist, word_count=4):
    """
    Generates 2 strong, memorable Diceware-style passphrase suggestions.
    
    1. Select 4 random words using secrets.choice(wordlist).
    2. Insert random separators (numbers/symbols) between words.
    3. Generate 2 variants:
       - Variant 1: First letter of each word capitalized (Title Case)
       - Variant 2: One random full word in uppercase
    4. Calculate the entropy score for each generated passphrase.
    """
    if not wordlist or len(wordlist) < word_count:
        return []

    # --- Variant 1: Title Case Words ---
    words_v1 = [secrets.choice(wordlist).capitalize() for _ in range(word_count)]
    passphrase_v1 = _join_words_with_separators(words_v1)
    entropy_v1 = calculate_entropy(passphrase_v1)
    strength_v1 = get_strength_label(entropy_v1)

    # --- Variant 2: Single Word Emphasis (One Word All-Caps) ---
    raw_words_v2 = [secrets.choice(wordlist).lower() for _ in range(word_count)]
    caps_index = secrets.randbelow(word_count)
    words_v2 = [
        w.upper() if i == caps_index else w
        for i, w in enumerate(raw_words_v2)
    ]
    passphrase_v2 = _join_words_with_separators(words_v2)
    entropy_v2 = calculate_entropy(passphrase_v2)
    strength_v2 = get_strength_label(entropy_v2)

    return [
        {
            "passphrase": passphrase_v1,
            "variant_name": "Title Case Words",
            "entropy": entropy_v1,
            "strength": strength_v1,
            "explanation": "High entropy from 4 capitalized words separated by random numbers/symbols."
        },
        {
            "passphrase": passphrase_v2,
            "variant_name": "Single Word Emphasis",
            "entropy": entropy_v2,
            "strength": strength_v2,
            "explanation": "High entropy with one full-caps word for enhanced human recall."
        }
    ]


def format_suggestions_panel(suggestions):
    """
    Scaffold (Agent):
    Renders the generated passphrase suggestions inside a rich Panel.
    """
    if not suggestions:
        return None

    render_items = []
    render_items.append("[bold yellow]Why passphrases?[/] [dim]Combining random dictionary words with symbols produces high mathematical entropy while remaining easy for humans to remember.[/]\n")

    for i, item in enumerate(suggestions, start=1):
        p_str = item.get("passphrase", "")
        v_name = item.get("variant_name", f"Option {i}")
        entropy = item.get("entropy", 0.0)
        strength = item.get("strength", "Strong")
        exp = item.get("explanation", "")

        render_items.append(f"[bold cyan]Suggestion {i} ({v_name}):[/] [bold white]{p_str}[/]")
        render_items.append(f"  [dim]Entropy: {entropy} bits | Rating: [green]{strength}[/green][/]")
        if exp:
            render_items.append(f"  [italic dim white]{exp}[/]")
        render_items.append("") # spacer

    if render_items:
        render_items.pop()

    return Panel(
        Group(*render_items),
        title="[bold green]Strong Passphrase Recommendations[/]",
        border_style="green",
        expand=False
    )
