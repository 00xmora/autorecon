#!/usr/bin/env python3

import os
import subprocess
import requests
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor

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
        print(f"{RED}Error running command: {command}{NC}")
        raise e

def setup_project(project_name):
    project_path = Path(project_name)
    project_path.mkdir(parents=True, exist_ok=True)
    print(f"{GREEN}{BOLD}[+] Project directory created: {project_name}{NC}")
    return project_path

def setup_domain_directory(project_path, domain):
    target_path = project_path / domain
    target_path.mkdir(parents=True, exist_ok=True)
    os.chdir(target_path)
    print(f"{BLUE}[+] Directory created: {project_path}/{domain}{NC}")
    return target_path

def passive_subdomain_enum(domain, threads=20):
    print(f"{YELLOW}[+] Running passive subdomain enumeration with {threads} threads...{NC}")
    commands = [
        (f"amass enum -d {domain} -o amassoutput.txt", "amassoutput.txt"),
        (f"subfinder -d {domain} -o subfinder.txt", "subfinder.txt"),
        (f"sublist3r -d {domain} -o sublist3r.txt", "sublist3r.txt")
    ]
    
    # Run commands concurrently
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(run_command, cmd, True, outfile): outfile 
                  for cmd, outfile in commands}
        for future in futures:
            try:
                future.result()  # Wait for completion and catch exceptions
            except Exception as e:
                print(f"{RED}Error in thread for {futures[future]}: {e}{NC}")
    
    # Process results
    with open("amassoutput.txt") as f:
        amass = [line.split()[0] for line in f if "(FQDN)" in line]
    with open("subfinder.txt") as f:
        subfinder = [line.strip() for line in f]
    with open("sublist3r.txt") as f:
        sublist3r = [line.strip() for line in f]
    
    # Combine and deduplicate
    all_subdomains = set(amass + subfinder + sublist3r)
    with open("domains.txt", "w") as f:
        for sub in all_subdomains:
            f.write(f"{sub}\n")
    
    # Clean up
    for file in ["amassoutput.txt", "subfinder.txt", "sublist3r.txt"]:
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
    
    run_command(f"cat domains | waybackurls > wayback.txt", silent=True)
    run_command(f"katana -list domains -d 5 -jc -o katana.txt", silent=True)
    run_command(f"cat domains | waymore > waymore.txt", silent=True)
    run_command(f"echo {domain} | waybackrobots -recent > waybackrobots.txt", silent=True)
    
    jslinks(domains=domains_list, output="js_endpoints.txt", recursive=recursive, headers=headers)
    
    all_urls = set()
    for file in ["wayback.txt", "katana.txt", "waymore.txt", "waybackrobots.txt", "js_endpoints.txt"]:
        if os.path.exists(file):
            with open(file) as f:
                all_urls.update(line.strip() for line in f if line.strip())
    
    with open("urls.txt", "w") as f:
        f.write("\n".join(sorted(all_urls)))
    
    for file in ["wayback.txt", "katana.txt", "waymore.txt", "waybackrobots.txt", "js_endpoints.txt"]:
        if os.path.exists(file):
            os.remove(file)
    print(f"{GREEN}[+] URL discovery and crawling completed (sorted and deduplicated){NC}")

def autorecon(project_name=None, domains=None, crawl=False, recursive=False, headers=None, threads=4):
    print_banner()
    
    if not project_name:
        print(f"{RED}{BOLD}Error: Project name (-n) is required{NC}")
        return
    
    project_path = setup_project(project_name)
    time.sleep(2)
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