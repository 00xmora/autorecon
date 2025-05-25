#!/usr/bin/env python3

import os
import subprocess
import requests
import re
import json
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import configparser

# Define colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m'
BOLD = '\033[1m'

# Load configuration
config = configparser.ConfigParser()
config_file = 'config.ini'
if os.path.exists(config_file):
    config.read(config_file)
else:
    config['API_KEYS'] = {
        'pentest_tools': '',
        'securitytrails': '',
        'virustotal': '',
        'dnsdumpster':'',
        'crtsh':'',
        'subdomainfinder':'',
        'findsubdomains':'',
        'netcraft':'',
        'socradar':''
    }
    with open(config_file, 'w') as f:
        config.write(f)
    print(f"{YELLOW}[+] Created default config.ini. Please add your API keys if available.{NC}")

PENTEST_API_KEY = config['API_KEYS'].get('pentest_tools', '')
SECURITYTRAILS_API_KEY = config['API_KEYS'].get('securitytrails', '')
VIRUSTOTAL_API_KEY = config['API_KEYS'].get('virustotal', '')

def print_banner():
    print(f"{CYAN}{BOLD}")
    print(r"                                                    ")
    print(r"                _        _____                      ")
    print(r"     /\        | |      |  __ \                     ")
    print(r"    /  \  _   _| |_ ___ | |__) |___  ___ ___  _ __  ")
    print(r"   / /\ \| | | | __/ _ \|  _  // _ \/ __/ _ \| '_ \ ")
    print(r"  / ____ \ |_| | || (_) | | \ \  __/ (_| (_) | | | |")
    print(r" /_/    \_\__,_|\__\___/|_|  \_\___|\___\___/|_| |_|")
    print(f"{NC}")
    print(f"{YELLOW}{BOLD}By: omar samy{NC}")
    print(f"{BLUE}{BOLD}Twitter: @omarsamy10{NC}")
    print("===================================================\n")

def run_command(command, silent=False, output_file=None):
    try:
        if silent and output_file:
            with open(output_file, 'w') as f:
                subprocess.run(command, shell=True, check=True, stdout=f, stderr=subprocess.DEVNULL)
        elif silent:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error running command: {command} - {e}{NC}")
        return False
    return True

def setup_project(project_name):
    project_path = Path(project_name).resolve()
    project_path.mkdir(parents=True, exist_ok=True)
    print(f"{GREEN}{BOLD}[+] Project directory created: {project_name}{NC}")
    return project_path

def setup_domain_directory(project_path, domain):
    target_path = (project_path / domain).resolve()
    target_path.mkdir(parents=True, exist_ok=True)
    os.chdir(target_path)
    print(f"{BLUE}[+] Directory created: {project_path}/{domain}{NC}")
    return target_path

def get_subdomains_from_free_services(target):
    subdomains = set()

    # 1. Pentest-Tools.com (API if key, else web)
    if PENTEST_API_KEY:
        headers = {"X-API-Key": PENTEST_API_KEY}
        base_url = "https://pentest-tools.com/api"
        try:
            response = requests.post(f"{base_url}/targets", json={"name": target, "type": "domain"}, headers=headers)
            target_id = response.json().get("id")
            scan_data = {"target_id": target_id, "tool": "subdomain_finder"}
            response = requests.post(f"{base_url}/scans", json=scan_data, headers=headers)
            scan_id = response.json().get("scan_id")
            while True:
                response = requests.get(f"{base_url}/scans/{scan_id}", headers=headers)
                data = response.json()
                if data.get("status") == "finished":
                    subdomains.update(data.get("results", {}).get("subdomains", []))
                    break
                time.sleep(10)
        except Exception as e:
            print(f"{RED}Error with Pentest-Tools API: {e}{NC}")
    else:
        try:
            url = f"https://pentest-tools.com/information-gathering/find-subdomains-of-domain?domain={target}"
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            for div in soup.select("div.subdomain-result"):
                subdomain = div.text.strip()
                if subdomain.endswith(f".{target}"):
                    subdomains.add(subdomain)
            print(f"{GREEN}[+] Retrieved subdomains from Pentest-Tools web{NC}")
        except Exception as e:
            print(f"{RED}Error with Pentest-Tools web: {e}{NC}")

    # 2. DNSdumpster.com
    try:
        response = requests.get("https://dnsdumpster.com", timeout=10)
        csrf_token = re.search(r'name="csrfmiddlewaretoken" value="(.+?)"', response.text).group(1)
        data = {"csrfmiddlewaretoken": csrf_token, "targetip": target}
        headers = {"Referer": "https://dnsdumpster.com"}
        response = requests.post("https://dnsdumpster.com", data=data, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        for td in soup.select("td.col-md-4"):
            subdomain = td.text.strip()
            if subdomain.endswith(f".{target}"):
                subdomains.add(subdomain)
    except Exception as e:
        print(f"{RED}Error with DNSdumpster: {e}{NC}")

    # 3. Nmmapper.com (manual retrieval due to CAPTCHA)
    print(f"{YELLOW}[+] Nmmapper.com requires manual retrieval: https://www.nmmapper.com/subdomains{NC}")

    # 4. SecurityTrails.com (API if key)
    if SECURITYTRAILS_API_KEY:
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        try:
            response = requests.get(f"https://api.securitytrails.com/v1/domain/{target}/subdomains", headers=headers)
            data = response.json()
            for sub in data.get("subdomains", []):
                subdomains.add(f"{sub}.{target}")
        except Exception as e:
            print(f"{RED}Error with SecurityTrails: {e}{NC}")

    # 5. Crt.sh
    try:
        response = requests.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=10)
        for entry in response.json():
            name = entry.get("name_value", "").strip()
            if name.endswith(f".{target}"):
                subdomains.add(name)
    except Exception as e:
        print(f"{RED}Error with Crt.sh: {e}{NC}")

    # 6. SubdomainFinder.c99.nl (manual retrieval)
    print(f"{YELLOW}[+] SubdomainFinder.c99.nl requires manual retrieval: https://subdomainfinder.c99.nl{NC}")

    # 7. VirusTotal.com (API if key)
    if VIRUSTOTAL_API_KEY:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/domains/{target}/subdomains", headers=headers)
            data = response.json()
            for sub in data.get("data", []):
                subdomains.add(sub.get("id"))
        except Exception as e:
            print(f"{RED}Error with VirusTotal: {e}{NC}")

    # 8. FindSubDomains.com (manual retrieval)
    print(f"{YELLOW}[+] FindSubDomains.com requires manual retrieval: https://findsubdomains.com{NC}")

    # 9. Netcraft.com
    try:
        response = requests.get(f"https://searchdns.netcraft.com/?host=*.{target}", timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        for a in soup.select("a[href*='site=']"):
            subdomain = re.search(r"site=([^&]+)", a["href"]).group(1)
            if subdomain.endswith(f".{target}"):
                subdomains.add(subdomain)
    except Exception as e:
        print(f"{RED}Error with Netcraft: {e}{NC}")

    # 10. Spyse/SOCRadar
    try:
        response = requests.get(f"https://api.socradar.io/tools/subdomains?domain={target}", timeout=10)
        data = response.json()
        subdomains.update(data.get("subdomains", []))
    except Exception as e:
        print(f"{RED}Error with SOCRadar: {e}{NC}")

    return subdomains

def passive_subdomain_enum(domain, threads=20):
    print(f"{YELLOW}[+] Running passive subdomain enumeration with {threads} threads...{NC}")
    commands = [
        (f"amass enum -passive -d {domain} -o amassoutput.txt", "amassoutput.txt"),
        (f"subfinder -d {domain} -o subfinder.txt", "subfinder.txt"),
        (f"sublist3r -d {domain} -o sublist3r.txt", "sublist3r.txt")
    ]
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(run_command, cmd, True, outfile): outfile 
                  for cmd, outfile in commands}
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"{RED}Error in thread for {futures[future]}: {e}{NC}")
    
    run_command("cat amassoutput.txt subfinder.txt sublist3r.txt | sort -u >> domains.txt ","domains.txt")
    run_command("rm amassoutput.txt subfinder.txt sublist3r.txt")

def filter_live_domains():
    print(f"{YELLOW}[+] Filtering live domains...{NC}")
    if os.path.exists("domains.txt"):
        if run_command("cat domains.txt | httpx -silent -o domain.live", silent=True):
            print(f"{GREEN}[+] Live domains filtered{NC}")
        else:
            print(f"{RED}[!] Failed to filter live domains{NC}")
    else:
        print(f"{RED}[!] domains.txt not found, skipping live domain filtering{NC}")

def active_subdomain_enum(domain):
    print(f"{YELLOW}[+] Running active subdomain enumeration with dnsrecon...{NC}")
    try:
        dns_output_file = "dns_servers.txt"
        # Use Google's public DNS server to fetch NS records
        run_command(f"dig @8.8.8.8 NS {domain} +short > {dns_output_file}", silent=True)
        
        dns_servers = set()
        if os.path.exists(dns_output_file):
            with open(dns_output_file, "r") as f:
                dns_servers = {line.strip().rstrip('.') for line in f if line.strip()}
            os.remove(dns_output_file)
        
        ns_ips = []
        if dns_servers:
            for ns in dns_servers:
                ip_output_file = f"ns_ip_{ns}.txt"
                run_command(f"dig @8.8.8.8 A {ns} +short > {ip_output_file}", silent=True)
                if os.path.exists(ip_output_file):
                    with open(ip_output_file, "r") as f:
                        ips = [line.strip() for line in f if line.strip() and re.match(r"^\d+\.\d+\.\d+\.\d+$", line)]
                        if ips:
                            ns_ips.append(ips[0])  # Take the first IP for each NS
                    os.remove(ip_output_file)
        
        wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
        if not os.path.exists(wordlist):
            print(f"{RED}[!] Wordlist not found: {wordlist}{NC}")
            return
        
        live_domains = set()
        if os.path.exists("domain.live"):
            with open("domain.live", "r") as dl:
                live_domains = set(dl.read().splitlines())
        
        if ns_ips:
            # Log all NS IPs in a single line for readability
            ns_list_str = ",".join(ns_ips)
            print(f"{BLUE}[+] Querying name servers: -n {ns_list_str}{NC}")
            
            # Run dnsrecon for each NS IP individually
            for i, ns_ip in enumerate(ns_ips):
                ns_option = f"-n {ns_ip}"
                dnsrecon_output = f"dnsrecon_output_{i}.json"
                cmd = f"dnsrecon -d {domain} -t brt -D {wordlist} {ns_option} --lifetime 10 --threads 50 -j {dnsrecon_output} -f"
                
                if run_command(cmd, silent=True):
                    if os.path.exists(dnsrecon_output):
                        try:
                            with open(dnsrecon_output, "r") as f:
                                data = json.load(f)
                                for record in data:
                                    if record.get("type") in ["A", "CNAME"] and record.get("name", "").endswith(f".{domain}"):
                                        live_domains.add(record.get("name"))
                        except json.JSONDecodeError:
                            print(f"{RED}[!] Failed to parse dnsrecon JSON output for {dnsrecon_output}{NC}")
                        os.remove(dnsrecon_output)
                else:
                    print(f"{RED}[!] Failed to run dnsrecon with {ns_option}{NC}")
        else:
            print(f"{YELLOW}[!] No authoritative DNS server IPs resolved, using system resolvers{NC}")
            dnsrecon_output = "dnsrecon_output.json"
            cmd = f"dnsrecon -d {domain} -t brt -D {wordlist} --lifetime 10 --threads 50 -j {dnsrecon_output} -f"
            if run_command(cmd, silent=True):
                if os.path.exists(dnsrecon_output):
                    try:
                        with open(dnsrecon_output, "r") as f:
                            data = json.load(f)
                            for record in data:
                                if record.get("type") in ["A", "CNAME"] and record.get("name", "").endswith(f".{domain}"):
                                    live_domains.add(record.get("name"))
                    except json.JSONDecodeError:
                        print(f"{RED}[!] Failed to parse dnsrecon JSON output{NC}")
                    os.remove(dnsrecon_output)
            else:
                print(f"{RED}[!] Failed to run dnsrecon with system resolvers{NC}")
        
        with open("domain.live", "w") as f:
            f.write("\n".join(sorted(live_domains)))
        print(f"{GREEN}[+] Active subdomain enumeration completed with dnsrecon{NC}")
    except Exception as e:
        print(f"{RED}[!] Error in active subdomain enumeration: {e}{NC}")

def fetch_js_files(url, headers):
    try:
        response = requests.get(url, headers=headers, timeout=10)
        js_pattern = re.compile(r'src=["\'](.*?\.js.*?)["\']', re.IGNORECASE)
        return [urljoin(url, js_file) for js_file in js_pattern.findall(response.text)]
    except Exception as e:
        print(f"{YELLOW}[+] Error fetching JS files from {url}: {e}{NC}")
        return []

def extract_endpoints(js_url, headers):
    patterns = [
        re.compile(r'https?:\/\/(?:[a-zA-Z0-9.-]+)\.[a-zA-Z0-9.-]+(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?'),
        re.compile(r'\/(?:api|v\d+|graphql|gql|rest|wp-json|endpoint|service|data|public|private|internal|external)(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?'),
        re.compile(r'(?<![\/\w])(?:api|v\d+|graphql|gql|rest|wp-json|endpoint|service|data|public|private|internal|external)(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?(?![a-zA-Z0-9_-])'),
        re.compile(r'(["\'])([a-zA-Z][a-zA-Z0-9_-]{2,}\/[a-zA-Z0-9_-]{2,}(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?)(\1)'),
        re.compile(r'(?:"[^"]*"|\'[^\']*\'|)(?<![\w\/])([a-zA-Z][a-zA-Z0-9_-]{1,}\/[a-zA-Z0-9_-]{2,}(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?)(?![\w-])'),
        re.compile(r'(?<!\/)([a-zA-Z][a-zA-Z0-9_-]*\.(?:php|asp|jsp|aspx|cfm|cgi|pl|py|rb|do|action))(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?\b', re.IGNORECASE),
    ]
    try:
        response = requests.get(js_url, headers=headers, timeout=10)
        endpoints = set()
        for pattern in patterns:
            matches = pattern.findall(response.text)
            if pattern.pattern.startswith(r'(["\'])'):
                endpoints.update(match[1] for match in matches)
            else:
                endpoints.update(matches)
        return endpoints
    except Exception as e:
        print(f"{YELLOW}[+] Error extracting endpoints from {js_url}: {e}{NC}")
        return set()

def normalize_endpoint(endpoint, base_url):
    parsed_base = urlparse(base_url)
    base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
    
    if endpoint.startswith(('http://', 'https://')):
        return endpoint
    elif endpoint.startswith('/'):
        return urljoin(base_domain, endpoint)
    elif '.' in endpoint and not endpoint.startswith('/'):
        if not endpoint.startswith(('http://', 'https://')):
            return f"https://{endpoint}"
        return endpoint
    else:
        return urljoin(base_domain, endpoint)

def jslinks(domains, output="js_endpoints.txt", recursive=False, headers=None):
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    }
    headers = headers if headers else default_headers
    
    urls_to_crawl = [f"https://{d}" for d in domains if not d.startswith(('http://', 'https://'))] + \
                   [d for d in domains if d.startswith(('http://', 'https://'))]
    
    found_endpoints = set()
    if os.path.exists(output):
        with open(output, "r") as f:
            found_endpoints.update(line.strip() for line in f if line.strip())
    
    visited_js = set()
    queue = urls_to_crawl.copy()

    while queue:
        url = queue.pop(0)
        js_files = fetch_js_files(url, headers)
        for js in js_files:
            if js not in visited_js:
                visited_js.add(js)
                endpoints = extract_endpoints(js, headers)
                normalized_endpoints = {normalize_endpoint(ep, js) for ep in endpoints}
                found_endpoints.update(normalized_endpoints)
                if recursive:
                    for endpoint in normalized_endpoints:
                        if endpoint.endswith('.js') and endpoint not in visited_js and endpoint not in queue:
                            queue.append(endpoint)
        time.sleep(1)
    
    with open(output, "w") as f:
        f.write("\n".join(sorted(found_endpoints)))
    print(f"{GREEN}[+] JS endpoints saved to {output} (sorted and deduplicated){NC}")
    
    return list(found_endpoints)

def crawl_urls(domain, domains_list, recursive=False, headers=None):
    print(f"{YELLOW}[+] Running URL discovery and crawling...{NC}")
    
    for cmd, outfile in [
        ("cat domains | waybackurls", "wayback.txt"),
        ("katana -list domains -d 5 -jc", "katana.txt"),
        ("cat domains | waymore", "waymore.txt"),
        (f"echo {domain} | waybackrobots -recent", "waybackrobots.txt")
    ]:
        if not run_command(f"{cmd} > {outfile}", silent=True):
            print(f"{RED}[!] Failed to run {cmd}{NC}")
    
    jslinks(domains=domains_list, output="js_endpoints.txt", recursive=recursive, headers=headers)
    
    all_urls = set()
    for file in ["wayback.txt", "katana.txt", "waymore.txt", "waybackrobots.txt", "js_endpoints.txt"]:
        if os.path.exists(file):
            with open(file, 'r', errors='ignore') as f:
                all_urls.update(line.strip() for line in f if line.strip())
    
    domain_pattern = re.compile(rf'https?://(?:[a-zA-Z0-9-]+\.)*{re.escape(domain)}(?:/|$|\?)')
    filtered_urls = {url for url in all_urls if domain_pattern.match(url)}
    
    with open("urls.txt", "w") as f:
        f.write("\n".join(sorted(filtered_urls)))
    
    for file in ["wayback.txt", "katana.txt", "waymore.txt", "waybackrobots.txt", "js_endpoints.txt"]:
        if os.path.exists(file):
            os.remove(file)
    print(f"{GREEN}[+] URL discovery and crawling completed (sorted and deduplicated, filtered for {domain}){NC}")

def autorecon(project_name=None, domains=None, crawl=False, recursive=False, headers=None, threads=4):
    print_banner()
    
    if not project_name:
        print(f"{RED}{BOLD}Error: Project name (-n) is required{NC}")
        return
    
    project_path = setup_project(project_name)
    if not domains and not crawl:
        print(f"{YELLOW}[+] No domains (-d) or crawling (-c) requested. Nothing to do.{NC}")
        return
    
    if domains:
        if isinstance(domains, str):
            domains = [domains]
        
        for domain in domains:
            print(f"{CYAN}{BOLD}\n[+] Processing domain: {domain}{NC}")
            setup_domain_directory(project_path, domain)
            
            passive_subdomain_enum(domain, threads)
            filter_live_domains()
            active_subdomain_enum(domain)
            
            if crawl:
                if os.path.exists("domain.live"):
                    with open("domain.live") as f:
                        domains_list = f.read().splitlines()
                    crawl_urls(domain, domains_list, recursive=recursive, headers=headers)
                else:
                    print(f"{RED}[!] domain.live not found, skipping crawling{NC}")
            
            os.chdir(project_path)
    
    elif crawl:
        print(f"{YELLOW}[+] Crawling requested but no domains provided. Please provide domains with -d.{NC}")
    
    print(f"{GREEN}{BOLD}\n[+] All tasks completed. Results in '{project_name}' directory{NC}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AutoRecon in Python")
    parser.add_argument("-n", "--project-name", help="Project name")
    parser.add_argument("-d", "--domains", nargs="*", help="List of domains")
    parser.add_argument("-c", "--crawl", action="store_true", help="Enable all crawling")
    parser.add_argument("-r", "--recursive", action="store_true", help="Enable recursive JS crawling")
    parser.add_argument("-H", "--header", action="append", help="Custom headers (format: 'Header-Name: value')")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads for concurrent execution (default: 4)")
    args = parser.parse_args()
    
    custom_headers = {}
    if args.header:
        for h in args.header:
            try:
                key, value = h.split(":", 1)
                custom_headers[key.strip()] = value.strip()
            except ValueError:
                print(f"❌ Invalid header format: {h} (should be 'Header-Name: value')")
                exit(1)
    
    autorecon(
        project_name=args.project_name,
        domains=args.domains,
        crawl=args.crawl,
        recursive=args.recursive,
        headers=custom_headers,
        threads=args.threads
    )