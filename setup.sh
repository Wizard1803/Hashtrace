#!/bin/bash

echo "[*] Installing Python requirements..."
pip3 install -r requirements.txt

echo "[*] Setting up Wordlists directory..."
mkdir -p Wordlists
cd Wordlists

if [ -f "rockyou.txt" ]; then
    echo "[+] rockyou.txt already exists."
else
    echo "[*] Downloading rockyou.txt.tar.gz..."
    curl -L -o rockyou.txt.tar.gz https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz
    
    echo "[*] Extracting rockyou.txt..."
    tar -xf rockyou.txt.tar.gz
    
    echo "[*] Cleaning up..."
    rm rockyou.txt.tar.gz
    
    echo "[+] rockyou.txt setup complete."
fi

cd ..
echo "[+] Setup complete! You can now run: python3 main.py"
