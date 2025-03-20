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
sudo apt install -y git curl wget python3 python3-venv pipx golang libcurl4-openssl-dev libssl-dev unzip

pipx ensurepath

# Install Python-based tools using pipx
echo -e "${YELLOW}${BOLD}[+] Installing Python-based tools with pipx...${NC}"
pipx install waymore
pipx install uro
pipx install waybackrobots

# Install essential tools
TOOLS=(amass subfinder sublist3r httpx ffuf waybackurls katana aquatone seclists)
for TOOL in "${TOOLS[@]}"; do
    if ! command_exists "$TOOL"; then
        echo -e "${YELLOW}${BOLD}[+] Installing $TOOL...${NC}"
        case "$TOOL" in
            amass|seclists)
                sudo apt install -y "$TOOL";;
            subfinder|httpx|ffuf|waybackurls|katana)
                go install -v "github.com/projectdiscovery/${TOOL}/cmd/${TOOL}@latest"
                sudo cp ~/go/bin/${TOOL} /usr/local/bin/;;
            aquatone)
                wget https://github.com/michenriksen/aquatone/releases/latest/download/aquatone_linux_amd64.zip -O /tmp/aquatone.zip
                unzip /tmp/aquatone.zip -d /tmp/aquatone
                sudo cp /tmp/aquatone/aquatone /usr/local/bin/
                sudo chmod +x /usr/local/bin/aquatone;;
            sublist3r)
                git clone https://github.com/aboul3la/Sublist3r.git /tmp/Sublist3r
                sudo python3 /tmp/Sublist3r/setup.py install
                sudo cp /tmp/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
                sudo chmod +x /usr/local/bin/sublist3r;;
        esac
    else
        echo -e "${GREEN}${BOLD}[+] $TOOL is already installed.${NC}"
    fi
done

# Cleanup
echo -e "${YELLOW}${BOLD}[+] Cleaning up temporary files...${NC}"
rm -rf /tmp/Sublist3r /tmp/aquatone /tmp/aquatone.zip

echo -e "${GREEN}${BOLD}[+] All tools installed successfully!${NC}"
