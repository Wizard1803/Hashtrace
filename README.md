# Hashtrace

**Hashtrace** is an advanced, threat-model-aware Password Analyzer CLI built in Python. 

Unlike basic password strength meters that rely purely on naive length-based entropy math, Hashtrace evaluates passwords against realistic offensive security techniques. It actively penalizes common human patterns, checks against massive known-breach databases, and provides realistic time-to-crack estimates across four different attacker threat models.

<p align="left">
  <img src="https://skillicons.dev/icons?i=python,bash,linux,windows" alt="Tech Stack" />
</p>

## Features (v2.0)

* **HaveIBeenPwned (HIBP) Integration:** Securely queries the HIBP API (using k-Anonymity) to check if the exact password has been leaked in public data breaches.
* **Local Wordlist Checking:** Fast lookups against local dictionaries (e.g., `rockyou.txt`) to instantly flag compromised passwords.
* **Advanced Pattern Detection:**
  * **Mutation & Leetspeak:** Detects common substitutions (`p@ssw0rd123`) and hybrid dictionary mutations.
  * **Keyboard Walks:** Catches horizontal keyboard mashes (e.g., `qwerty`, `asdfgh`).
  * **Date Patterns:** Detects dictionary words appended with 4-digit years (e.g., `superman1998`).
  * **Repeating Characters:** Heavily penalizes stuttering patterns (e.g., `!!!!!`).
* **Offensive Security Entropy Scoring:** Uses aggressive multiplier penalties and a "Hard Cap" system to ensure that long but predictable passwords (like `thisisaverylongpassword`) are never artificially rated as "Strong".
* **Threat Model Crack Times:** Calculates estimated time-to-crack across four realistic attacker scenarios:
  1. Online Attack (Throttled) - *100 guesses/sec*
  2. Offline Attack (Slow Hash, e.g. bcrypt) - *10,000 guesses/sec*
  3. Offline Attack (Fast Hash, e.g. MD5) - *10 Billion guesses/sec*
  4. Massive GPU Cluster (Nation-State/Cartel) - *100 Trillion guesses/sec*
* **Beautiful CLI UI:** Built with `rich` for dynamic coloring, tables, and loading spinners.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/hashtrace.git
   cd hashtrace
   ```

2. Install the required Python packages:
   ```bash
   pip install rich requests
   ```

3. **Add your Wordlist:**
   Create a `Wordlists` folder in the root directory and place your dictionary file inside it. By default, the script looks for `rockyou.txt`:
   ```bash
   mkdir Wordlists
   # Place rockyou.txt inside the Wordlists folder
   ```

## Usage

Run the main script to launch the CLI interface:

```bash
python main.py
```

You will be greeted by the Hashtrace banner and prompted to enter passwords for analysis. The tool will provide a detailed Target Analysis Report for each password. Type `quit` to exit.

## Project Structure

* `main.py`: The entry point. Handles the CLI loop, UI rendering, and user input via `rich`.
* `checker.py`: Contains the logic for the HIBP API, local wordlist loading, and structural pattern detection (leetspeak, mutations, keyboard walks, dates).
* `analyzer.py`: Contains the core mathematical logic for calculating base entropy, mapping strength tiers, and calculating threat-model crack times.

## Acknowledgments

* **Troy Hunt & HaveIBeenPwned**: For providing the incredible (and free) API that powers the public breach detection.
* **Textualize / Rich**: For the fantastic Python library used to build the beautiful and responsive CLI interface.

## Disclaimer

This tool is designed for educational purposes, defensive security auditing, and threat modeling. Do not enter your *actual* personal passwords into any command-line tool or script. 

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.