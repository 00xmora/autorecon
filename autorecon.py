#!/usr/bin/env python3

import os
import subprocess
import requests
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

# Define colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m'
BOLD = '\033[1m'

def print_banner():
    print(f"{CYAN}{BOLD}")
    print("                                                    ")
    print("                _        _____                      ")
    print("     /\        | |      |  __ \                     ")
    print("    /  \  _   _| |_ ___ | |__) |___  ___ ___  _ __  ")
    print("   / /\ \| | | | __/ _ \|  _  // _ \/ __/ _ \| '_ \ ")
    print("  / ____ \ |_| | || (_) | | \ \  __/ (_| (_) | | | |")
    print(" /_/    \_\__,_|\__\___/|_|  \_\___|\___\___/|_| |_|")
    print(f"{NC}")
    print(f"{YELLOW}{BOLD}By: omar samy{NC}")
    print(f"{BLUE}{BOLD}Twitter: @omarsamy10{NC}")
    print("===================================================\n")

def run_command(command, silent=False):
    try:
        if silent:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error running command: {command}{NC}")
        raise e

def setup_project(project_name):
    project_path = Path(project_name)
    project_path.mkdir(parents=True, exist_ok=True)
    os.chdir(project_path)
    print(f"{GREEN}{BOLD}[+] Project directory created: {project_name}{NC}")
    return project_path

def setup_domain_directory(project_path, domain):
    target_path = project_path / domain
    target_path.mkdir(parents=True, exist_ok=True)
    os.chdir(target_path)
    print(f"{BLUE}[+] Directory created: {project_path}/{domain}{NC}")
    return target_path

def passive_subdomain_enum(domain):
    print(f"{YELLOW}[+] Running passive subdomain enumeration...{NC}")
    processes = [
        f"amass enum -d {domain} -o amassoutput.txt",
        f"subfinder -d {domain} -o subfinder.txt",
        f"sublist3r -d {domain} -o sublist3r.txt",
        f"dnsenum {domain} > dnsenum.txt 2>&1"
    ]
    for cmd in processes:
        run_command(cmd, silent=True)
    
    with open("amassoutput.txt") as f:
        amass = [line.split()[0] for line in f if "(FQDN)" in line]
    with open("dnsenum.txt") as f:
        dnsenum = [line.strip() for line in f if domain in line and line.strip().endswith(".")]
    
    with open("domains.txt", "w") as f:
        for sub in set(amass + dnsenum):
            f.write(f"{sub}\n")
    for file in ["amassoutput.txt", "subfinder.txt", "sublist3r.txt", "dnsenum.txt"]:
        if os.path.exists(file):
            os.remove(file)
    print(f"{GREEN}[+] Passive subdomain enumeration completed{NC}")

def filter_live_domains():
    print(f"{YELLOW}[+] Filtering live domains...{NC}")
    run_command("cat domains.txt | httpx -silent -o domain.live", silent=True)
    os.remove("domains.txt")
    print(f"{GREEN}[+] Live domains filtered{NC}")

def active_subdomain_enum(domain):
    print(f"{YELLOW}[+] Running active subdomain enumeration...{NC}")
    run_command(f"ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u https://FUZZ.{domain} -c -mc all -fs 0 -o ffuf.txt")
    with open("domains", "w") as f:
        with open("domain.live") as dl, open("ffuf.txt") as ff:
            domains_set = set(dl.read().splitlines() + ff.read().splitlines())
            f.write("\n".join(domains_set))
    for file in ["domain.live", "ffuf.txt"]:
        if os.path.exists(file):
            os.remove(file)
    print(f"{GREEN}[+] Active subdomain enumeration completed{NC}")

def fetch_js_files(url, headers):
    try:
        response = requests.get(url, headers=headers, timeout=10)
        js_pattern = re.compile(r'src=["\'](.*?\.js.*?)["\']', re.IGNORECASE)
        return [urljoin(url, js_file) for js_file in js_pattern.findall(response.text)]
    except Exception:
        print(f"{YELLOW}[+] Error fetching JS files from {url}{NC}")
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
    except Exception:
        print(f"{YELLOW}[+] Error extracting endpoints from {js_url}{NC}")
        return set()

def normalize_endpoint(endpoint, base_url):
    """Normalize an endpoint to a full URL using the base URL of the JS file."""
    parsed_base = urlparse(base_url)
    base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
    
    if endpoint.startswith(('http://', 'https://')):
        return endpoint  # Already a full URL
    elif endpoint.startswith('/'):
        return urljoin(base_domain, endpoint)  # Absolute path, prepend base domain
    elif '.' in endpoint and not endpoint.startswith('/'):
        # Likely a subdomain or full domain without protocol (e.g., api.example.com/path)
        if not endpoint.startswith(('http://', 'https://')):
            return f"https://{endpoint}"
        return endpoint
    else:
        return urljoin(base_domain, endpoint)  # Relative path, resolve with base URL

def jslinks(domains, output="js_endpoints.txt", recursive=False, headers=None):
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    }
    headers = headers if headers else default_headers
    
    urls_to_crawl = [f"https://{d}" for d in domains if not d.startswith(('http://', 'https://'))] + \
                   [d for d in domains if d.startswith(('http://', 'https://'))]
    
    found_endpoints = set()
    # Load existing endpoints if file exists
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
                # Normalize endpoints with the JS file's base URL
                normalized_endpoints = {normalize_endpoint(ep, js) for ep in endpoints}
                found_endpoints.update(normalized_endpoints)
                if recursive:
                    for endpoint in normalized_endpoints:
                        if endpoint.endswith('.js') and endpoint not in visited_js and endpoint not in queue:
                            queue.append(endpoint)
        time.sleep(1)
    
    # Sort and write (append mode if file existed, otherwise overwrite)
    with open(output, "w") as f:
        f.write("\n".join(sorted(found_endpoints)))
    print(f"{GREEN}[+] JS endpoints saved to {output} (sorted and deduplicated){NC}")
    
    return list(found_endpoints)

def crawl_urls(domain, domains_list, recursive=False, headers=None):
    print(f"{YELLOW}[+] Running URL discovery and crawling...{NC}")
    
    # Run standard crawling tools
    run_command(f"cat domains | waybackurls > wayback.txt", silent=True)
    run_command(f"katana -list domains -d 5 -jc -o katana.txt", silent=True)
    run_command(f"cat domains | waymore > waymore.txt", silent=True)
    run_command(f"echo {domain} | waybackrobots -recent > waybackrobots.txt", silent=True)
    
    # Run JS links crawling
    jslinks(domains=domains_list, output="js_endpoints.txt", recursive=recursive, headers=headers)
    
    # Merge all results, sort, and deduplicate
    all_urls = set()
    for file in ["wayback.txt", "katana.txt", "waymore.txt", "waybackrobots.txt", "js_endpoints.txt"]:
        if os.path.exists(file):
            with open(file) as f:
                all_urls.update(line.strip() for line in f if line.strip())
    
    with open("urls.txt", "w") as f:
        f.write("\n".join(sorted(all_urls)))
    
    # Clean up temporary files
    for file in ["wayback.txt", "katana.txt", "waymore.txt", "waybackrobots.txt", "js_endpoints.txt"]:
        if os.path.exists(file):
            os.remove(file)
    print(f"{GREEN}[+] URL discovery and crawling completed (sorted and deduplicated){NC}")

def autorecon(project_name=None, domains=None, crawl=False, recursive=False, headers=None):
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
            
            # Subdomain enumeration if domains provided
            passive_subdomain_enum(domain)
            filter_live_domains()
            active_subdomain_enum(domain)
            
            # Crawling if requested
            if crawl:
                with open("domains") as f:
                    domains_list = f.read().splitlines()
                crawl_urls(domain, domains_list, recursive=recursive, headers=headers)
            
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
        headers=custom_headers
    )