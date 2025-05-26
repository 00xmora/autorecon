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

echo -e "${YELLOW}${BOLD}[+] Installing necessary system packages...${NC}"
sudo apt install -y git curl wget python3 python3-venv python3-pip golang libcurl4-openssl-dev libssl-dev unzip dnsutils

# Ensure pipx is installed and in PATH
echo -e "${YELLOW}${BOLD}[+] Installing pipx...${NC}"
python3 -m pip install --user pipx --break-system-packages || echo -e "${YELLOW}[!] pipx might already be installed or there was a minor issue installing. Continuing...${NC}"
python3 -m pipx ensurepath
# Source the updated PATH (important for pipx to be found immediately)
# This might not fully apply to the current shell script execution, but helps for subsequent sessions.
echo -e "${YELLOW}Attempting to source .bashrc or .profile for updated PATH...${NC}"
if [ -f "$HOME/.bashrc" ]; then
    source "$HOME/.bashrc"
elif [ -f "$HOME/.profile" ]; then
    source "$HOME/.profile"
fi
export PATH="$PATH:$HOME/.local/bin:$HOME/go/bin" # Ensure common paths are in PATH for script execution

# Install Python-based tools using pipx
echo -e "${YELLOW}${BOLD}[+] Installing Python-based tools with pipx...${NC}"
pipx install waymore || echo -e "${YELLOW}[!] waymore might already be installed or failed. Continuing...${NC}"
pipx install uro || echo -e "${YELLOW}[!] uro might already be installed or failed. Continuing...${NC}"

# Install Go-based tools
echo -e "${YELLOW}${BOLD}[+] Installing Go-based tools...${NC}"
go install github.com/owasp-amass/amass/v3/...@latest || echo -e "${YELLOW}[!] amass might already be installed or failed. Continuing...${NC}"
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || echo -e "${YELLOW}[!] subfinder might already be installed or failed. Continuing...${NC}"
go install github.com/projectdiscovery/httpx/cmd/httpx@latest || echo -e "${YELLOW}[!] httpx might already be installed or failed. Continuing...${NC}"
go install github.com/tomnomnom/waybackurls@latest || echo -e "${YELLOW}[!] waybackurls might already be installed or failed. Continuing...${NC}"
go install github.com/projectdiscovery/katana/cmd/katana@latest || echo -e "${YELLOW}[!] katana might already be installed or failed. Continuing...${NC}"
go install github.com/mhmdiaa/waybackrobots@latest || echo -e "${YELLOW}[!] waybackrobots might already be installed or failed. Continuing...${NC}"
go install github.com/ffuf/ffuf/v2@latest || echo -e "${YELLOW}[!] ffuf might already be installed or failed. Continuing...${NC}"
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || echo -e "${YELLOW}[!] naabu might already be installed or failed. Continuing...${NC}"
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest || echo -e "${YELLOW}[!] nuclei might already be installed or failed. Continuing...${NC}"
go install github.com/OJ/gobuster/v3/...@latest || echo -e "${YELLOW}[!] gobuster might already be installed or failed. Continuing...${NC}"


# Move Go binaries to /usr/local/bin
echo -e "${YELLOW}${BOLD}[+] Moving Go binaries to /usr/local/bin/...${NC}"
# Iterate through common go install locations and link
GO_BIN_PATHS=(
    "$HOME/go/bin"
    "$(go env GOPATH)/bin"
)
for GOBIN in "${GO_BIN_PATHS[@]}"; do
    if [ -d "$GOBIN" ]; then
        for tool in amass subfinder httpx waybackurls katana waybackrobots ffuf naabu nuclei gobuster; do
            if [ -f "$GOBIN/$tool" ]; then
                echo -e "${BLUE}  - Copying $tool from $GOBIN${NC}"
                sudo cp "$GOBIN/$tool" /usr/local/bin/ || echo -e "${RED}[!] Failed to copy $tool. Permission denied?${NC}"
            fi
        done
        break # Assuming all tools are in one of these paths
    fi
done

# Install other tools (Python based via git clone)
echo -e "${YELLOW}${BOLD}[+] Installing additional Python tools from Git repositories...${NC}"

# sublist3r
if ! command_exists "sublist3r.py"; then # Check for the script name directly
    echo -e "${YELLOW}[+] Installing Sublist3r...${NC}"
    git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r
    sudo pip3 install -r /opt/Sublist3r/requirements.txt --break-system-packages
    # Create a symlink or wrapper script in /usr/local/bin
    sudo ln -sf /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
    sudo chmod +x /usr/local/bin/sublist3r
else
    echo -e "${GREEN}${BOLD}[+] Sublist3r is already installed or accessible.${NC}"
fi

# dnsrecon
if ! command_exists "dnsrecon"; then
    echo -e "${YELLOW}[+] Installing dnsrecon...${NC}"
    git clone https://github.com/darkoperator/dnsrecon.git /opt/dnsrecon
    cd /opt/dnsrecon
    sudo pip3 install -r requirements.txt --break-system-packages
    sudo python3 setup.py install
    cd - > /dev/null # Go back to previous directory silently
else
    echo -e "${GREEN}${BOLD}[+] dnsrecon is already installed.${NC}"
fi

# seclists
if ! dpkg -s seclists &> /dev/null; then # Check if seclists package is installed
    echo -e "${YELLOW}[+] Installing seclists...${NC}"
    sudo apt install -y seclists
else
    echo -e "${GREEN}${BOLD}[+] seclists is already installed.${NC}"
fi

# paramspider
if ! command_exists "paramspider"; then
    echo -e "${YELLOW}[+] Installing ParamSpider...${NC}"
    git clone https://github.com/devanshbatham/ParamSpider.git /opt/ParamSpider
    sudo pip3 install -r /opt/ParamSpider/requirements.txt --break-system-packages
    # Create a symlink to make it globally executable
    sudo ln -sf /opt/ParamSpider/paramspider.py /usr/local/bin/paramspider
    sudo chmod +x /usr/local/bin/paramspider
else
    echo -e "${GREEN}${BOLD}[+] ParamSpider is already installed or accessible.${NC}"
fi

# SecretFinder
if [ ! -d "/opt/SecretFinder" ]; then # Check if directory exists
    echo -e "${YELLOW}[+] Installing SecretFinder...${NC}"
    git clone https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder
    sudo pip3 install -r /opt/SecretFinder/requirements.txt --break-system-packages
    # Create a symlink to make it globally executable
    sudo ln -sf /opt/SecretFinder/SecretFinder.py /usr/local/bin/secretfinder
    sudo chmod +x /usr/local/bin/secretfinder
else
    echo -e "${GREEN}${BOLD}[+] SecretFinder is already installed or accessible.${NC}"
fi

# Nuclei Templates Update
echo -e "${YELLOW}${BOLD}[+] Updating Nuclei templates...${NC}"
if command_exists "nuclei"; then
    nuclei -update-templates || echo -e "${RED}[!] Failed to update Nuclei templates. Please check your internet connection or Nuclei installation.${NC}"
else
    echo -e "${YELLOW}[!] Nuclei not found, skipping template update. Please install Nuclei first.${NC}"
fi

# Install autorecon globally
echo -e "${YELLOW}${BOLD}[+] Installing AutoRecon globally...${NC}"
# Ensure autorecon.py and config.ini are in the current directory
if [ -f "autorecon.py" ] && [ -f "config.ini" ]; then
    chmod +x autorecon.py
    sudo cp autorecon.py /usr/local/bin/autorecon
    
    # Ensure config.ini is placed where autorecon can find it, or update autorecon.py to look in /etc or ~/.config
    # For simplicity, let's put it in /usr/local/bin alongside the script
    sudo cp config.ini /usr/local/bin/config.ini
    
    echo -e "${GREEN}${BOLD}[+] AutoRecon installed to /usr/local/bin/autorecon${NC}"
    echo -e "${YELLOW}Please check and update API keys in /usr/local/bin/config.ini.${NC}"
else
    echo -e "${RED}${BOLD}[!] Error: autorecon.py or config.ini not found in current directory. Cannot install AutoRecon globally.${NC}"
    exit 1
fi

echo -e "${GREEN}${BOLD}[+] All tools and AutoRecon installation attempted!${NC}"
echo -e "${GREEN}${BOLD}[+] You can now run 'autorecon -h' to see usage instructions.${NC}"
echo -e "${YELLOW}${BOLD}[!] IMPORTANT: Ensure your PATH includes $HOME/.local/bin and $HOME/go/bin. Restart your terminal if tools are not found.${NC}"
echo -e "${YELLOW}${BOLD}[!] IMPORTANT: Edit /usr/local/bin/config.ini to add your API keys!${NC}"