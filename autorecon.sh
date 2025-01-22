#!/bin/bash

# Define colors and styles
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'
UNDERLINE='\033[4m'

# Custom banner
echo -e "${CYAN}${BOLD}"
echo "                                                    "
echo "                _        _____                      "
echo "     /\        | |      |  __ \                     "
echo "    /  \  _   _| |_ ___ | |__) |___  ___ ___  _ __  "
echo "   / /\ \| | | | __/ _ \|  _  // _ \/ __/ _ \| '_ \ "
echo "  / ____ \ |_| | || (_) | | \ \  __/ (_| (_) | | | |"
echo " /_/    \_\__,_|\__\___/|_|  \_\___|\___\___/|_| |_|"
echo -e "${NC}"
echo -e "${YELLOW}${BOLD}By: omar samy${NC}"
echo -e "${BLUE}${BOLD}Twitter: @omarsamy10${NC}"
echo -e "===================================================\n"

# Check if project name and at least one domain are provided
if [ -z "$1" ] || [ -z "$2" ]; then
    echo -e "${RED}${BOLD}Usage: $0 <project_name> <domain1> [domain2] [domain3] ...${NC}"
    exit 1
fi

PROJECT_NAME=$1
shift  # Shift arguments to the left to start processing domains

# Create a directory for the project
mkdir -p $PROJECT_NAME
cd $PROJECT_NAME

echo -e "${GREEN}${BOLD}[+] Project directory created: $PROJECT_NAME${NC}"

# Loop through each domain provided
for TARGET in "$@"; do
    echo -e "${CYAN}${BOLD}\n[+] Processing domain: $TARGET${NC}"

    # Create a directory for the current domain
    mkdir -p $TARGET
    cd $TARGET

    echo -e "${BLUE}[+] Directory created: $PROJECT_NAME/$TARGET${NC}"

    # Step 1: Passive Subdomain Enumeration 
    echo -e "${YELLOW}[+] Running passive subdomain enumeration...${NC}"
    amass enum -active -d $TARGET -o amassoutput.txt > /dev/null 2>&1 &
    subfinder -d $TARGET -o subfinder.txt > /dev/null 2>&1 &
    sublist3r -d $TARGET -o sublist3r.txt > /dev/null 2>&1 &

    # Wait for all passive enumeration tools to finish
    wait

    # Merge and sort results
    cat amassoutput.txt |grep "(FQDN)" | awk '{print $1}' > amass.txt
    cat amass.txt subfinder.txt sublist3r.txt | sort -u > domains.txt
    rm  amass.txt subfinder.txt sublist3r.txt 
    echo -e "${GREEN}[+] Passive subdomain enumeration completed. Results saved to domains.txt${NC}"

    # Filter live domains
    echo -e "${YELLOW}[+] Filtering live domains...${NC}"
    cat domains.txt | httpx -o domain.live > /dev/null 2>&1
    rm  domains.txt
    echo -e "${GREEN}[+] Live domains filtered. Results saved to domain.live${NC}"

    # Step 2: Active Subdomain Enumeration
    echo -e "${YELLOW}[+] Running active subdomain enumeration...${NC}"
    ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u "https://FUZZ.$TARGET" -c -t 30 -mc all -fs 0 -o ffuf.txt > /dev/null 2>&1

    # Merge all subdomains
    cat domain.live ffuf.txt | sort -u > domains
    rm  domain.live 
    echo -e "${GREEN}[+] Active subdomain enumeration completed. Results saved to domains${NC}"

    # Step 3: URL Discovery and Crawling
    echo -e "${YELLOW}[+] Running URL discovery and crawling...${NC}"
    cat domain.live | waybackurls > wayback.txt & 
    katana -list domain.live -o katana.txt > /dev/null 2>&1 &
    cat domain.live | waymore > waymore.txt &
    cat domain.live | waybackrobots > waybackrobots.txt &

    # Wait for all URL discovery tools to finish
    wait

    # Merge all URL results and remove duplicates
    cat wayback.txt katana.txt waymore.txt waybackrobots.txt | sort -u | uro > urls.txt
    rm  wayback.txt katana.txt waymore.txt waybackrobots.txt
    echo -e "${GREEN}[+] URL discovery and crawling completed. Results saved to urls.txt${NC}"

    # Step 4: Inspect results with Aquatone
    echo -e "${YELLOW}[+] Running Aquatone for inspection...${NC}"
    cat domains | aquatone > /dev/null 2>&1 

    echo -e "${GREEN}[+] Aquatone inspection completed. Results saved to aquatone/ directory${NC}"

    echo -e "${MAGENTA}${BOLD}[+] Done processing domain: $TARGET. Results are saved in the '$PROJECT_NAME/$TARGET' directory.${NC}"

    # Move back to the project directory to process the next domain
    cd ..
done

echo -e "${GREEN}${BOLD}\n[+] All domains processed. Results are saved in the '$PROJECT_NAME' directory.${NC}"