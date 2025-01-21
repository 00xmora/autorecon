#!/bin/bash

# Define colors and styles
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Function to check if a command is installed
command_exists() {
    command -v "$1" &> /dev/null
}

# Update package lists
echo -e "${YELLOW}${BOLD}[+] Updating package lists...${NC}"
sudo apt update

# Install tools using apt
echo -e "${YELLOW}${BOLD}[+] Installing tools using apt...${NC}"
sudo apt install -y git curl wget python3 python3-pip python3-venv golang libcurl4-openssl-dev libssl-dev

# Update pip and setuptools
echo -e "${YELLOW}${BOLD}[+] Updating pip and setuptools...${NC}"
pip install --upgrade pip setuptools --break-system-packages

# Install Python packages with --break-system-packages
echo -e "${YELLOW}${BOLD}[+] Installing Python packages...${NC}"
pip install scrapy waymore uro --break-system-packages

# Install Amass
if ! command_exists amass; then
    echo -e "${YELLOW}${BOLD}[+] Installing Amass...${NC}"
    sudo apt install -y amass
else
    echo -e "${GREEN}${BOLD}[+] Amass is already installed.${NC}"
fi

# Install Subfinder
if ! command_exists subfinder; then
    echo -e "${YELLOW}${BOLD}[+] Installing Subfinder...${NC}"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    sudo cp ~/go/bin/subfinder /usr/local/bin/
else
    echo -e "${GREEN}${BOLD}[+] Subfinder is already installed.${NC}"
fi

# Install Sublist3r
if ! command_exists sublist3r; then
    echo -e "${YELLOW}${BOLD}[+] Installing Sublist3r...${NC}"
    git clone https://github.com/aboul3la/Sublist3r.git /tmp/Sublist3r
    sudo python3 /tmp/Sublist3r/setup.py install
    sudo cp /tmp/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
    sudo chmod +x /usr/local/bin/sublist3r
else
    echo -e "${GREEN}${BOLD}[+] Sublist3r is already installed.${NC}"
fi

# Install httpx
if ! command_exists httpx; then
    echo -e "${YELLOW}${BOLD}[+] Installing httpx...${NC}"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    sudo cp ~/go/bin/httpx /usr/local/bin/
else
    echo -e "${GREEN}${BOLD}[+] httpx is already installed.${NC}"
fi

# Install ffuf
if ! command_exists ffuf; then
    echo -e "${YELLOW}${BOLD}[+] Installing ffuf...${NC}"
    go install -v github.com/ffuf/ffuf@latest
    sudo cp ~/go/bin/ffuf /usr/local/bin/
else
    echo -e "${GREEN}${BOLD}[+] ffuf is already installed.${NC}"
fi

# Install waybackurls
if ! command_exists waybackurls; then
    echo -e "${YELLOW}${BOLD}[+] Installing waybackurls...${NC}"
    go install -v github.com/tomnomnom/waybackurls@latest
    sudo cp ~/go/bin/waybackurls /usr/local/bin/
else
    echo -e "${GREEN}${BOLD}[+] waybackurls is already installed.${NC}"
fi

# Install katana
if ! command_exists katana; then
    echo -e "${YELLOW}${BOLD}[+] Installing katana...${NC}"
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    sudo cp ~/go/bin/katana /usr/local/bin/
else
    echo -e "${GREEN}${BOLD}[+] katana is already installed.${NC}"
fi

# Install Aquatone
if ! command_exists aquatone; then
    echo -e "${YELLOW}${BOLD}[+] Installing Aquatone...${NC}"
    wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip -O /tmp/aquatone.zip
    unzip /tmp/aquatone.zip -d /tmp/aquatone
    sudo cp /tmp/aquatone/aquatone /usr/local/bin/
    sudo chmod +x /usr/local/bin/aquatone
else
    echo -e "${GREEN}${BOLD}[+] Aquatone is already installed.${NC}"
fi

# Install seclists (for ffuf wordlist)
if [ ! -d "/usr/share/seclists" ]; then
    echo -e "${YELLOW}${BOLD}[+] Installing seclists...${NC}"
    sudo apt install -y seclists
else
    echo -e "${GREEN}${BOLD}[+] seclists is already installed.${NC}"
fi

# Clean up temporary files
echo -e "${YELLOW}${BOLD}[+] Cleaning up temporary files...${NC}"
rm -rf /tmp/Sublist3r /tmp/aquatone /tmp/aquatone.zip /tmp/crawley

echo -e "${GREEN}${BOLD}[+] All tools installed successfully!${NC}"