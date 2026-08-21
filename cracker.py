import hashlib
import re
from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Prompt

def identify_hash_type(hash_str):
    # identify hash algorithm by length and charset
    cleaned = hash_str.strip().lower()
    
    if not re.fullmatch(r'[0-9a-f]+', cleaned):
        return "Unknown"

    length = len(cleaned)
    if length == 32:
        return "MD5/NTLM"
    elif length == 40:
        return "SHA-1"
    elif length == 64:
        return "SHA-256"
    elif length == 128:
        return "SHA-512"
    else:
        return "Unknown"


import struct

def _md4(data: bytes) -> str:
    # Pure-Python RFC 1320 MD4 implementation for NTLM support on Python 3.13 / OpenSSL 3.0+
    msg = bytearray(data)
    orig_len_bits = (8 * len(msg)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0)
    msg += struct.pack('<Q', orig_len_bits)

    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

    def _left_rotate(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z

    for i in range(0, len(msg), 64):
        X = struct.unpack('<16I', msg[i:i+64])
        AA, BB, CC, DD = A, B, C, D

        # Round 1
        s1 = [3, 7, 11, 19]
        for j in range(16):
            A = _left_rotate((A + F(B, C, D) + X[j]) & 0xFFFFFFFF, s1[j % 4])
            A, B, C, D = D, A, B, C

        # Round 2
        s2 = [3, 5, 9, 13]
        idx2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for j in range(16):
            A = _left_rotate((A + G(B, C, D) + X[idx2[j]] + 0x5A827999) & 0xFFFFFFFF, s2[j % 4])
            A, B, C, D = D, A, B, C

        # Round 3
        s3 = [3, 9, 11, 15]
        idx3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for j in range(16):
            A = _left_rotate((A + H(B, C, D) + X[idx3[j]] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[j % 4])
            A, B, C, D = D, A, B, C

        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    return struct.pack('<4I', A, B, C, D).hex()


def hash_word(word, algorithm):

    algo = algorithm.upper()
    try:
        if algo == "MD5":
            return hashlib.md5(word.encode("utf-8")).hexdigest()
        elif algo == "SHA-1" or algo == "SHA1":
            return hashlib.sha1(word.encode("utf-8")).hexdigest()
        elif algo == "SHA-256" or algo == "SHA256":
            return hashlib.sha256(word.encode("utf-8")).hexdigest()
        elif algo == "SHA-512" or algo == "SHA512":
            return hashlib.sha512(word.encode("utf-8")).hexdigest()
        elif algo == "NTLM":
            try:
                return hashlib.new("md4", word.encode("utf-16le")).hexdigest()
            except (ValueError, Exception):
                return _md4(word.encode("utf-16le"))
        else:
            return None
    except Exception:
        return None


def crack_hash(target_hash, algorithm, wordlist):
    # in-memory dictionary search
    target = target_hash.strip().lower()
    for word in wordlist:
        if hash_word(word, algorithm) == target:
            return True, word
    return False, None


def resolve_ambiguity(target_hash, console):
    # handle 32-hex ambiguity (MD5 vs NTLM)
    console.print("\n[yellow]Ambiguity Detected:[/] Target hash is 32 hex characters, which matches both [bold cyan]MD5[/] and [bold cyan]NTLM[/].")
    console.print("  [1] MD5 (Standard Unix/Web hash)")
    console.print("  [2] NTLM (Windows Active Directory / SAM hash)")
    console.print("  [3] I don't know (Attempt both)")
    
    choice = Prompt.ask("\n[bold cyan]Select algorithm to attempt[/]", choices=["1", "2", "3"], default="3")
    
    if choice == "1":
        return ["MD5"]
    elif choice == "2":
        return ["NTLM"]
    else:
        return ["MD5", "NTLM"]


def run_hash_cracker(target_hash, wordlist, console):

    cleaned_hash = target_hash.strip().lower()
    detected_type = identify_hash_type(cleaned_hash)

    if detected_type == "Unknown":
        console.print(f"\n[bold red]Error:[/] Unknown or unsupported hash format for '{target_hash}'.")
        console.print("[dim]Supported types: MD5 (32 hex), NTLM (32 hex), SHA-1 (40 hex), SHA-256 (64 hex), SHA-512 (128 hex)[/]\n")
        return False

    console.print(f"\n[bold cyan]Target Hash:[/] {cleaned_hash}")
    console.print(f"[bold cyan]Identified Type:[/] [bold green]{detected_type}[/]")

    # Ambiguity resolution
    if detected_type == "MD5/NTLM":
        algorithms_to_try = resolve_ambiguity(cleaned_hash, console)
    else:
        algorithms_to_try = [detected_type]

    found = False
    cracked_plaintext = None
    successful_algo = None

    for algo in algorithms_to_try:
        with console.status(f"[bold cyan]Searching wordlist using {algo}...[/]"):
            matched, plaintext = crack_hash(cleaned_hash, algo, wordlist)
            if matched:
                found = True
                cracked_plaintext = plaintext
                successful_algo = algo
                break

    if found:
        render_items = [
            f"[bold green]CRACKED SUCCESSFULLY![/]\n",
            f"[cyan]Target Hash:[/] {cleaned_hash}",
            f"[cyan]Algorithm:[/]   [bold magenta]{successful_algo}[/]",
            f"[cyan]Plaintext:[/]   [bold green]{cracked_plaintext}[/]"
        ]
        panel = Panel(
            Group(*render_items),
            title="[bold green]Hash Recovery Report[/]",
            border_style="green",
            expand=False
        )
        console.print()
        console.print(panel)
        console.print()
        return True
    else:
        render_items = [
            f"[bold red]HASH NOT FOUND IN WORDLIST[/]\n",
            f"[cyan]Target Hash:[/] {cleaned_hash}",
            f"[cyan]Algorithms Checked:[/] {', '.join(algorithms_to_try)}\n",
            f"[yellow]Important Security Caveat:[/] A wordlist miss does [bold underline]NOT[/] mean the password is mathematically safe.",
            f"It only proves that this password was not present in the current dictionary list ({len(wordlist)} entries)."
        ]
        panel = Panel(
            Group(*render_items),
            title="[bold red]Hash Recovery Failed[/]",
            border_style="red",
            expand=False
        )
        console.print()
        console.print(panel)
        console.print()
        return False
