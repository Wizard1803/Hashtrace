@echo off
echo [*] Installing Python requirements...
pip install -r requirements.txt

echo [*] Setting up Wordlists directory...
if not exist "Wordlists" mkdir Wordlists
cd Wordlists

if exist "rockyou.txt" (
    echo [+] rockyou.txt already exists.
) else (
    echo [*] Downloading rockyou.txt.tar.gz...
    curl -L -o rockyou.txt.tar.gz https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz
    
    echo [*] Extracting rockyou.txt...
    tar -xf rockyou.txt.tar.gz
    
    echo [*] Cleaning up...
    del rockyou.txt.tar.gz
    
    echo [+] rockyou.txt setup complete.
)

cd ..
echo [+] Setup complete! You can now run: python main.py
