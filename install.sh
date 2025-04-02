#!/bin/bash

# Define colors and styles
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Enable error handling
set -e

# Function to check if a command is installed
command_exists() {
    command -v "$1" &> /dev/null
}

echo -e "${YELLOW}${BOLD}[+] Updating package lists...${NC}"
sudo apt update

echo -e "${YELLOW}${BOLD}[+] Installing necessary packages...${NC}"
sudo apt install -y git curl wget python3 python3-venv python3-pip golang libcurl4-openssl-dev libssl-dev unzip

# Ensure pipx is installed and in PATH
echo -e "${YELLOW}${BOLD}[+] Installing pipx...${NC}"
python3 -m pip install --user pipx --break-system-packages
python3 -m pipx ensurepath
# Source the updated PATH (might need to restart shell in some cases)
source ~/.bashrc || source ~/.bash_profile

# Install Python-based tools using pipx
echo -e "${YELLOW}${BOLD}[+] Installing Python-based tools with pipx...${NC}"
pipx install waymore
pipx install uro

# Install Go-based tools
echo -e "${YELLOW}${BOLD}[+] Installing Go-based tools...${NC}"
go install github.com/owasp-amass/amass/v3/...@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/mhmdiaa/waybackrobots@latest
go install github.com/ffuf/ffuf/v2@latest

# Move Go binaries to /usr/local/bin
sudo cp ~/go/bin/amass /usr/local/bin/
sudo cp ~/go/bin/subfinder /usr/local/bin/
sudo cp ~/go/bin/httpx /usr/local/bin/
sudo cp ~/go/bin/waybackurls /usr/local/bin/
sudo cp ~/go/bin/katana /usr/local/bin/
sudo cp ~/go/bin/waybackrobots /usr/local/bin/
sudo cp ~/go/bin/ffuf /usr/local/bin/

# Install other tools
echo -e "${YELLOW}${BOLD}[+] Installing additional tools...${NC}"
if ! command_exists "sublist3r"; then
    git clone https://github.com/aboul3la/Sublist3r.git /tmp/Sublist3r
    sudo python3 /tmp/Sublist3r/setup.py install
    sudo cp /tmp/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
    sudo chmod +x /usr/local/bin/sublist3r
else
    echo -e "${GREEN}${BOLD}[+] sublist3r is already installed.${NC}"
fi

if ! command_exists "seclists"; then
    sudo apt install -y seclists
else
    echo -e "${GREEN}${BOLD}[+] seclists is already installed.${NC}"
fi

# Install autorecon globally
echo -e "${YELLOW}${BOLD}[+] Installing AutoRecon globally...${NC}"
if [ -f "autorecon.py" ]; then
    chmod +x autorecon.py
    sudo mv autorecon.py /usr/local/bin/autorecon
    echo -e "${GREEN}${BOLD}[+] AutoRecon installed to /usr/local/bin/autorecon${NC}"
else
    echo -e "${RED}${BOLD}[!] Error: autorecon.py not found in current directory${NC}"
    exit 1
fi

# Cleanup
echo -e "${YELLOW}${BOLD}[+] Cleaning up temporary files...${NC}"
rm -rf /tmp/Sublist3r

echo -e "${GREEN}${BOLD}[+] All tools and AutoRecon installed successfully!${NC}"
echo -e "${GREEN}${BOLD}[+] You can now run 'autorecon' from anywhere.${NC}"