#!/bin/bash

# Check if target domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target.com>"
    exit 1
fi

TARGET=$1

# Create a directory for results
mkdir -p $TARGET
cd $TARGET

# Step 1: Passive Subdomain Enumeration
echo "[+] Runnin passive subdomain enumeration..."
amass enum -passive -d $TARGET -o amass.txt &
subfinder -d $TARGET -o subfinder.txt &
sublist3r -d $TARGET -o sublist3r.txt &

# Wait for all passive enumeration tools to finish
wait

# Merge and sort results
cat amass.tt subfinder.txt sublist3r.txt | sort -u > domains.txt

# Filter live domains
echo "[+] Filtering live domains..."
cat domains.txt | httpx -o domain.live

# Step 2: Active Subdomain Enumeration
echo "[+] Running active subdomain enumeration..."
ffuf -w /us/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u "https://FUZZ.$TARGET" -c -t 30 -mc all -fs 0 -o ffuf.txt

# Merge all subdomains
cat domain.live ffuf.txt | sort -u > domains

# Step 3: URL Discovery and Crawling
echo "[+] Running URL dscovery and crawling..."
cat domain.live | waybackurls | tee wayback.txt &
katana -list domain.live -o katana.txt &
cat domain.live | waymore | tee waymore.txt &
cat domain.live | crawley -all | tee crawley.txt &
at domain.live | waybackrobots | tee waybackrobots.txt &

# Wait for all URL discovery tools to finish
wait

# Merge all URL results and remove duplicates
cat wayback.txt katana.txt waymore.txt crawley.txt waybackrobots.txt | sort -u | uro > urls.xt

# Step 4: Inspect results with Aquatone
echo "[+] Running Aquatone for inspection..."
cat domain.live | aquatone

echo "[+] Done! Results are saved in the '$TARGET' directory."
