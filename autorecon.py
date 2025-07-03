#!/usr/bin/env python3

import os
import subprocess
import requests
import re
import json
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
import argparse

# Define colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m'
BOLD = '\033[1m'

# Tool config paths (these are defaults, tools will be checked in PATH)
# Ensure these paths are correctly set if your tools are installed elsewhere
SUBFINDER_CONFIG = Path.home() / '.config' / 'subfinder' / 'config.yaml'
AMASS_CONFIG = Path.home() / '.config' / 'amass' / 'config.ini'
HTTPX_CONFIG = Path.home() / '.config' / 'httpx' / 'config.yaml'
NUCLEI_TEMPLATES_PATH = Path.home() / 'nuclei-templates'
SECLISTS_PATH = '/usr/share/seclists' # General seclists path

def print_banner():
    """Prints the tool's banner."""
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
    print(f"{BLUE}{BOLD}Twitter: @00xmora{NC}")
    print("===================================================\n")

def run_command(command, silent=False, output_file=None, capture_output=False, check_install=None):
    """
    Runs a shell command.
    :param command: The command string to execute.
    :param silent: If True, suppress stdout and stderr to console.
    :param output_file: If provided, stdout is redirected to this file.
    :param capture_output: If True, captures stdout and returns it.
    :param check_install: If provided, it's the name of the tool to check if installed.
    :return: Tuple (success_boolean, output_string_if_captured)
    """
    if check_install:
        try:
            # Check if the tool is in PATH
            subprocess.run(["which", check_install], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            print(f"{RED}[!] Error: Tool '{check_install}' not found. Please install it and ensure it's in your PATH.{NC}")
            return False, None

    try:
        if capture_output:
            result = subprocess.run(command, shell=True, check=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return True, result.stdout.strip()
        elif silent and output_file:
            with open(output_file, 'w') as f:
                subprocess.run(command, shell=True, check=True, stdout=f, stderr=subprocess.DEVNULL)
        elif silent:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error running command: {command} - {e}{NC}")
        return False, None

    return True, None


def install_external_python_tool(tool_name, repo_url, script_name_in_repo, symlink_name):
    """Installs a Python-based external tool from a Git repository if it's not found."""
    print(f"{YELLOW}[+] Checking if {tool_name} is installed...{NC}")
    if run_command(f"which {symlink_name}", silent=True, capture_output=False)[0]:
        print(f"{GREEN}[+] {tool_name} is already installed.{NC}")
        return True
    
    print(f"{YELLOW}[!] {tool_name} not found. Attempting to install from {repo_url}...{NC}")
    install_dir = Path("/opt") / tool_name # Install to /opt to avoid permission issues in /usr/local/bin directly
    
    try:
        if not install_dir.exists():
            run_command(f"git clone {repo_url} {install_dir}", silent=True)
            print(f"{GREEN}[+] Cloned {tool_name} repository to {install_dir}{NC}")
        
        # Check for requirements.txt and install if present
        requirements_path = install_dir / "requirements.txt"
        if requirements_path.exists():
            print(f"{BLUE}[+] Installing Python dependencies for {tool_name}...{NC}")
            run_command(f"sudo pip3 install -r {requirements_path} --break-system-packages", silent=True)
            
        # Create a symlink to the main script in /usr/local/bin
        source_script = install_dir / script_name_in_repo
        symlink_path = Path("/usr/local/bin") / symlink_name
        
        if source_script.exists():
            run_command(f"sudo ln -sf {source_script} {symlink_path}", silent=True)
            run_command(f"sudo chmod +x {symlink_path}", silent=True)
            print(f"{GREEN}[+] Created symlink for {tool_name} at {symlink_path}{NC}")
        else:
            print(f"{RED}[!] Source script {source_script} not found for symlinking. Cannot create executable link.{NC}")
            return False
        
        if run_command(f"which {symlink_name}", silent=True, capture_output=False)[0]:
            print(f"{GREEN}[+] {tool_name} installed successfully!{NC}")
            return True
        else:
            print(f"{RED}[!] {tool_name} still not found in PATH after installation attempt. Please check manually.{NC}")
            return False

    except Exception as e:
        print(f"{RED}Error installing {tool_name}: {e}{NC}")
        return False

def is_subdomain_of(potential_sub, main_domain):
    """Checks if a potential_sub is a subdomain of main_domain or the main_domain itself."""
    return potential_sub == main_domain or potential_sub.endswith(f".{main_domain}")

def filter_and_normalize_entries(entries, main_target_domain, entry_type="url", exclude_extensions=None):
    """
    Filters, normalizes, and deduplicates a list of entries (URLs, domains, or IPs).
    Args:
        entries (iterable): List or set of strings (URLs, domain names, or IP addresses).
        main_target_domain (str): The primary domain for filtering (e.g., "example.com").
        entry_type (str): "url", "domain", or "ip" to apply specific filtering logic.
        exclude_extensions (list): List of file extensions to exclude if entry_type is "url".
    Returns:
        set: A set of normalized and filtered entries.
    """
    if exclude_extensions is None:
        exclude_extensions = ['.css', '.js', '.ico', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', 'woff2', '.ttf', '.eot', '.map', '.txt', '.xml', '.pdf']

    normalized_filtered_entries = set()
    
    for entry_str in entries:
        if not entry_str or len(entry_str) < 5: # Minimum reasonable length for an entry
            continue
        
        try:
            if entry_type == "domain":
                if is_subdomain_of(entry_str, main_target_domain):
                    normalized_filtered_entries.add(entry_str)
            
            elif entry_type == "url":
                parsed_url = urlparse(entry_str)
                
                if not parsed_url.scheme or not parsed_url.netloc:
                    continue

                if not is_subdomain_of(parsed_url.netloc, main_target_domain):
                    continue
                
                path_lower = parsed_url.path.lower()
                if any(path_lower.endswith(ext) for ext in exclude_extensions):
                    continue

                query_params = parse_qs(parsed_url.query)
                sorted_query = '&'.join(f"{k}={','.join(sorted(v))}" for k, v in sorted(query_params.items()))
                
                normalized_url = urlunparse(parsed_url._replace(fragment="", query=sorted_query))
                normalized_filtered_entries.add(normalized_url)
            
            elif entry_type == "ip":
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", entry_str):
                    normalized_filtered_entries.add(entry_str)
            
            else: # Fallback for other string types
                normalized_filtered_entries.add(entry_str)

        except Exception as e:
            print(f"{YELLOW}[!] Could not process entry '{entry_str}' as {entry_type}: {e}{NC}")
            continue
            
    return normalized_filtered_entries


def setup_project(project_name):
    """Creates the main project directory."""
    project_path = Path(project_name).resolve()
    project_path.mkdir(parents=True, exist_ok=True)
    print(f"{GREEN}{BOLD}[+] Project directory created: {project_name}{NC}")
    return project_path

def setup_domain_directory(project_path, domain):
    """Creates and navigates into the domain-specific directory within the project."""
    target_path = (project_path / domain).resolve()
    target_path.mkdir(parents=True, exist_ok=True)
    os.chdir(target_path)
    print(f"{BLUE}[+] Directory created: {project_path}/{domain}{NC}")
    return target_path

def passive_subdomain_enum(domain, threads=20):
    """Performs passive subdomain enumeration using various tools."""
    print(f"{YELLOW}[+] Running passive subdomain enumeration with {threads} threads...{NC}")
    
    temp_amass_file = "amass_raw.txt"
    temp_subfinder_file = "subfinder_raw.txt"
    temp_sublist3r_file = "sublist3r_raw.txt"

    commands = [
        (f"amass enum -passive -d {domain} -o {temp_amass_file}", temp_amass_file, "amass"),
        (f"subfinder -d {domain} -o {temp_subfinder_file}", temp_subfinder_file, "subfinder"),
        (f"sublist3r -d {domain} -o {temp_sublist3r_file}", temp_sublist3r_file, "sublist3r")
    ]
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for cmd, outfile, tool_name in commands:
            futures.append(executor.submit(run_command, cmd, True, outfile, False, tool_name))
        
        for future in futures:
            success, _ = future.result()
            if not success:
                pass
    
    all_subdomains = set()
    for temp_file in [temp_amass_file, temp_subfinder_file, temp_sublist3r_file]:
        if os.path.exists(temp_file):
            try:
                with open(temp_file, 'r') as f:
                    all_subdomains.update(line.strip() for line in f if line.strip())
                os.remove(temp_file)
            except Exception as e:
                print(f"{RED}Error reading or cleaning up {temp_file}: {e}{NC}")
    
    filtered_subdomains = filter_and_normalize_entries(all_subdomains, domain, entry_type="domain")

    if filtered_subdomains:
        with open("domains.txt", "w") as f:
            f.write("\n".join(sorted(filtered_subdomains)))
        print(f"{GREEN}[+] All passive subdomains collected and saved to domains.txt{NC}")
    else:
        print(f"{YELLOW}[!] No passive subdomains found.{NC}")

def filter_live_domains(main_target_domain):
    """Filters discovered domains to identify live and responsive web servers using httpx."""
    print(f"{YELLOW}[+] Filtering live domains with httpx...{NC}")
    if not os.path.exists("domains.txt"):
        print(f"{RED}[!] domains.txt not found, skipping live domain filtering{NC}")
        return

    live_subdomains_file = "domain.live"
    success, _ = run_command(
        f"cat domains.txt | httpx -silent -fc 400,401,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,421,422,423,424,425,426,428,429,431,451,500,501,502,503,504,505,506,507,508,510,511 -t 100 -o {live_subdomains_file}",
        silent=True, check_install="httpx"
    )
    
    if success:
        print(f"{GREEN}[+] Live domains filtered and saved to {live_subdomains_file}{NC}")
        success_ips, ips_output = run_command(
            f"cat domains.txt | httpx -silent -ip -json",
            silent=True, capture_output=True, check_install="httpx"
        )
        if success_ips and ips_output:
            unique_ips = set()
            try:
                for line in ips_output.splitlines():
                    try:
                        data = json.loads(line)
                        if 'ip' in data:
                            unique_ips.add(data['ip'])
                    except json.JSONDecodeError:
                        pass
                
                filtered_ips = filter_and_normalize_entries(unique_ips, main_target_domain, entry_type="ip")
                
                with open("ips.txt", "w") as f:
                    f.write("\n".join(sorted(filtered_ips)))
                print(f"{GREEN}[+] Extracted unique IPs to ips.txt{NC}")
            except Exception as e:
                print(f"{RED}[!] Error extracting IPs: {e}{NC}")
        else:
            print(f"{YELLOW}[!] No IPs extracted or httpx failed to output JSON.{NC}")
    else:
        print(f"{RED}[!] Failed to filter live domains with httpx. Check if httpx is installed and accessible.{NC}")

def _run_dnsrecon(domain, wordlist, ns_option, output_file, live_domains_set):
    """Helper function to run dnsrecon and parse its JSON output."""
    cmd = f"dnsrecon -d {domain} -t brt -D {wordlist} {ns_option} --lifetime 10 --threads 50 -j {output_file} -f"
    
    print(f"{BLUE}[+] Running: {cmd}{NC}")
    
    if run_command(cmd, silent=True, check_install="dnsrecon"):
        if os.path.exists(output_file):
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    for record in data:
                        if record.get("type") in ["A", "CNAME"] and record.get("name", "").endswith(f".{domain}"):
                            live_domains_set.add(record.get("name"))
                print(f"{GREEN}[+] Successfully parsed dnsrecon output from {output_file}{NC}")
            except json.JSONDecodeError:
                print(f"{RED}[!] Failed to parse dnsrecon JSON output for {output_file}. File might be empty or malformed.{NC}")
            except Exception as e:
                print(f"{RED}[!] Error reading {output_file}: {e}{NC}")
            finally:
                os.remove(output_file)
        else:
            print(f"{YELLOW}[!] dnsrecon output file {output_file} not found, even though command reported success.{NC}")
    else:
        print(f"{RED}[!] Failed to run dnsrecon with {ns_option}. Check if dnsrecon is installed and accessible.{NC}")


def active_subdomain_enum(domain, custom_wordlist_path=None):
    """Performs active subdomain enumeration using dnsrecon and ffuf."""
    print(f"{YELLOW}[+] Running active subdomain enumeration with dnsrecon and ffuf...{NC}")
    try:
        success, ns_records_str = run_command(f"dig @8.8.8.8 NS {domain} +short", silent=True, capture_output=True, check_install="dig")
        dns_servers = set()
        if success and ns_records_str:
            dns_servers = {line.strip().rstrip('.') for line in ns_records_str.splitlines() if line.strip()}
        
        ns_ips = []
        if dns_servers:
            print(f"{BLUE}[+] Resolved NS records for {domain}: {', '.join(dns_servers)}{NC}")
            for ns in dns_servers:
                success_ip, ip_str = run_command(f"dig @8.8.8.8 A {ns} +short", silent=True, capture_output=True, check_install="dig")
                if success_ip and ip_str:
                    ips = [line.strip() for line in ip_str.splitlines() if line.strip() and re.match(r"^\d+\.\d+\.\d+\.\d+$", line)]
                    if ips:
                        ns_ips.append(ips[0])
        
        wordlist_path_dnsrecon = Path(SECLISTS_PATH) / "Discovery" / "DNS" / "subdomains-top1million-110000.txt"
        wordlist_path_ffuf = Path(SECLISTS_PATH) / "Discovery" / "Web-Content" / "subdomains-top1million-110000.txt"

        if custom_wordlist_path and Path(custom_wordlist_path).exists():
            wordlist_dnsrecon = str(custom_wordlist_path)
            wordlist_ffuf = str(custom_wordlist_path)
            print(f"{BLUE}[+] Using custom wordlist for DNS recon and FFUF: {custom_wordlist_path}{NC}")
        else:
            wordlist_dnsrecon = str(wordlist_path_dnsrecon)
            wordlist_ffuf = str(wordlist_path_ffuf)
            if not Path(wordlist_dnsrecon).exists():
                print(f"{RED}[!] Default DNS wordlist not found: {wordlist_dnsrecon}. Please ensure Seclists is installed and configured.{NC}")
                return
            if not Path(wordlist_ffuf).exists():
                print(f"{RED}[!] Default FFUF wordlist not found: {wordlist_ffuf}. Please ensure Seclists is installed and configured.{NC}")
                wordlist_ffuf = None 
            print(f"{BLUE}[+] Using default wordlists.{NC}")

        live_domains = set()
        if os.path.exists("domain.live"):
            with open("domain.live", "r") as dl:
                live_domains = set(dl.read().splitlines())
        
        dnsrecon_futures = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            if ns_ips:
                ns_list_str = ",".join(ns_ips)
                print(f"{BLUE}[+] Querying name servers for dnsrecon: {ns_list_str}{NC}")
                for i, ns_ip in enumerate(ns_ips):
                    ns_option = f"-n {ns_ip}"
                    dnsrecon_output_file = f"dnsrecon_output_{i}.json"
                    dnsrecon_futures.append(executor.submit(_run_dnsrecon, domain, wordlist_dnsrecon, ns_option, dnsrecon_output_file, live_domains))
            else:
                print(f"{YELLOW}[!] No authoritative DNS server IPs resolved, using system resolvers for dnsrecon.{NC}")
                dnsrecon_output_file = "dnsrecon_output_system.json"
                dnsrecon_futures.append(executor.submit(_run_dnsrecon, domain, wordlist_dnsrecon, "", dnsrecon_output_file, live_domains))
            
            for future in dnsrecon_futures:
                future.result()

        if wordlist_ffuf:
            print(f"{YELLOW}[+] Running FFUF for virtual host enumeration...{NC}")
            ffuf_output_file = "ffuf_vhosts.json"
            ffuf_cmd = (
                f"ffuf -w {wordlist_ffuf}:FUZZ "
                f"-u http://{domain} "
                f"-H \"Host: FUZZ.{domain}\" "
                f"-mc all "
                f"-sf "
                f"-o {ffuf_output_file} -ot json"
            )
            print(f"{BLUE}[+] Running FFUF: {ffuf_cmd}{NC}")
            if run_command(ffuf_cmd, silent=True, check_install="ffuf"):
                if os.path.exists(ffuf_output_file):
                    try:
                        with open(ffuf_output_file, "r") as f:
                            ffuf_data = json.load(f)
                            for result in ffuf_data.get("results", []):
                                if result.get("status") in [200, 301, 302, 307, 308]:
                                    fuzzed_host = result.get("input", {}).get("FUZZ", "")
                                    if fuzzed_host:
                                        full_subdomain = f"{fuzzed_host}.{domain}"
                                        live_domains.add(full_subdomain)
                        print(f"{GREEN}[+] FFUF virtual host enumeration completed.{NC}")
                    except json.JSONDecodeError:
                        print(f"{RED}[!] Failed to parse FFUF JSON output for {ffuf_output_file}. File might be empty or malformed.{NC}")
                    except Exception as e:
                        print(f"{RED}[!] Error reading {ffuf_output_file}: {e}{NC}")
                    finally:
                        os.remove(ffuf_output_file)
                else:
                    print(f"{YELLOW}[!] FFUF output file {ffuf_output_file} not found.{NC}")
            else:
                print(f"{RED}[!] FFUF command failed. Ensure ffuf is installed and accessible.{NC}")

        filtered_live_domains = filter_and_normalize_entries(live_domains, domain, entry_type="domain")

        if filtered_live_domains:
            with open("domain.live", "w") as f:
                f.write("\n".join(sorted(filtered_live_domains)))
            print(f"{GREEN}[+] All active subdomains collected and saved to domain.live{NC}")
        else:
            print(f"{YELLOW}[!] No active subdomains found after dnsrecon and ffuf.{NC}")
            
    except Exception as e:
        print(f"{RED}[!] Error in active subdomain enumeration: {e}{NC}")


def crawl_urls(domain, domains_list, recursive=False, headers=None,
               enable_crawler=False, crawler_max_pages=10, crawler_output_format='json', crawler_headless=False):
    """Performs URL discovery using waybackurls, katana, waymore, waybackrobots, and jslinks."""
    print(f"{YELLOW}[+] Running URL discovery and crawling...{NC}")
    
    temp_domains_file = "temp_domains_for_crawling.txt"
    with open(temp_domains_file, "w") as f:
        f.write("\n".join(domains_list))

    commands = [
        (f"cat {temp_domains_file} | waybackurls", "wayback.txt", "waybackurls"),
        (f"katana -list {temp_domains_file} -d 5 -jc", "katana.txt", "katana"),
        (f"cat {temp_domains_file} | waymore", "waymore.txt", "waymore"),
        (f"echo {domain} | waybackrobots -recent", "waybackrobots.txt", "waybackrobots")
    ]
    
    with ThreadPoolExecutor(max_workers=len(commands)) as executor:
        futures = []
        for cmd, outfile, tool_name in commands:
            futures.append(executor.submit(run_command, f"{cmd} > {outfile}", silent=True, check_install=tool_name))
        
        for future in futures:
            success, _ = future.result()
            if not success:
                pass
    
    # Call external jslinks.py
    jslinks_output_file = "js_endpoints.txt"
    jslinks_domains_arg = " ".join(domains_list)
    jslinks_cmd = f"jslinks -d {jslinks_domains_arg} -o {jslinks_output_file}"
    if recursive:
        jslinks_cmd += " -r"
    if headers:
        for k, v in headers.items():
            jslinks_cmd += f" -H \"{k}: {v}\""
            
    print(f"{BLUE}[+] Running jslinks: {jslinks_cmd}{NC}")
    # install_external_python_tool is called in autorecon() main logic
    success, _ = run_command(jslinks_cmd, silent=True, check_install="jslinks")
    if success:
        print(f"{GREEN}[+] JS links discovery completed.{NC}")
    else:
        print(f"{RED}[!] Failed to run jslinks. Check installation or command.{NC}")


    # Call external crawler.py if enabled
    if enable_crawler:
        print(f"{YELLOW}[+] Running dynamic website crawling with crawler.py...{NC}")
        crawler_output_file = "crawler_endpoints.json"
        crawler_headers_str = ""
        if headers:
            for k, v in headers.items():
                crawler_headers_str += f" --header \"{k}: {v}\""
        
        start_url_for_crawler = domains_list[0] if domains_list else f"https://{domain}"
        if not start_url_for_crawler.startswith(('http://', 'https://')):
             start_url_for_crawler = f"https://{start_url_for_crawler}"

        crawler_cmd = (
            f"crawler -u {start_url_for_crawler} "
            f"-m {crawler_max_pages} "
            f"-o {crawler_output_file} "
            f"-f {crawler_output_format}"
        )
        if crawler_headless:
            crawler_cmd += " --headless"
        if crawler_headers_str:
            crawler_cmd += crawler_headers_str

        print(f"{BLUE}[+] Running crawler: {crawler_cmd}{NC}")
        # install_external_python_tool is called in autorecon() main logic
        # Run non-silently to show manual login prompt
        success, _ = run_command(crawler_cmd, silent=False, check_install="crawler")
        if success and os.path.exists(crawler_output_file):
            print(f"{GREEN}[+] Dynamic crawling with crawler.py completed.{NC}")
            try:
                with open(crawler_output_file, 'r') as f:
                    crawler_results = json.load(f)
                
                # Extract URLs from crawler results and add to all_urls
                # This will be merged with other URLs later
                # Temporarily store, will be filtered below.
                if 'all_urls' not in locals(): # Initialize if not already from other sources
                    all_urls = set()
                all_urls.update(entry['url'] for entry in crawler_results if 'url' in entry)

                os.remove(crawler_output_file)
            except json.JSONDecodeError:
                print(f"{RED}[!] Failed to parse crawler.py JSON output. Skipping adding to URLs.{NC}")
            except Exception as e:
                print(f"{RED}Error processing crawler.py output: {e}{NC}")
        else:
            print(f"{RED}[!] Failed to run crawler.py or output not found. Check installation or command.{NC}")
            
    all_urls = set()
    for file in ["wayback.txt", "katana.txt", "waymore.txt", "waybackrobots.txt", "js_endpoints.txt"]:
        if os.path.exists(file):
            with open(file, 'r', errors='ignore') as f:
                all_urls.update(line.strip() for line in f if line.strip())
            os.remove(file)
    
    # Merge with URLs from crawler if it ran
    if 'crawler_results' in locals():
        all_urls.update(entry['url'] for entry in crawler_results if 'url' in entry)

    filtered_urls = filter_and_normalize_entries(all_urls, domain, entry_type="url")

    with open("urls.txt", "w") as f:
        f.write("\n".join(sorted(filtered_urls)))
    
    if os.path.exists(temp_domains_file):
        os.remove(temp_domains_file)
    print(f"{GREEN}[+] URL discovery and crawling completed (sorted and deduplicated, filtered for {domain}){NC}")

def port_and_service_enum():
    """Conducts fast port scanning with naabu and detailed service detection with nmap."""
    print(f"{YELLOW}[+] Running port and service enumeration...{NC}")
    if not os.path.exists("ips.txt"):
        print(f"{RED}[!] ips.txt not found. Skipping port and service enumeration.{NC}")
        return

    naabu_output_file = "naabu_open_ports.txt"
    success_naabu, _ = run_command(
        f"cat ips.txt | naabu -silent -o {naabu_output_file} -p - -nmap-cli 'nmap -sV -sC -oX nmap_detailed_scan.xml'",
        silent=True, check_install="naabu"
    )
    
    if success_naabu and os.path.exists(naabu_output_file):
        print(f"{GREEN}[+] Naabu scan completed. Open ports saved to {naabu_output_file}. Detailed Nmap scan initiated (nmap_detailed_scan.xml).{NC}")
    else:
        print(f"{RED}[!] Failed to run naabu or output not found. Skipping detailed Nmap scan.{NC}")

def web_content_discovery(domain):
    """Performs web content discovery (directory brute-forcing) using gobuster."""
    print(f"{YELLOW}[+] Running web content discovery (gobuster/dirsearch)...{NC}")
    if not os.path.exists("domain.live"):
        print(f"{RED}[!] domain.live not found. Skipping web content discovery.{NC}")
        return

    wordlist = Path(SECLISTS_PATH) / "Discovery" / "Web-Content" / "common.txt"
    if not wordlist.exists():
        print(f"{RED}[!] Web content wordlist not found: {wordlist}. Please ensure Seclists is installed.{NC}")
        return

    live_domains_list = []
    with open("domain.live", "r") as f:
        live_domains_list = [line.strip() for line in f if line.strip()]

    gobuster_futures = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        for d in live_domains_list:
            cmd = f"gobuster dir -u {d} -w {wordlist} -t 50 -k" 
            print(f"{BLUE}[+] Running gobuster on {d}...{NC}")
            gobuster_futures.append(executor.submit(run_command, cmd, silent=True, capture_output=True, check_install="gobuster"))
    
        all_discovered_paths_raw = set()
        for i, future in enumerate(gobuster_futures):
            success, gobuster_output = future.result()
            if success and gobuster_output:
                for line in gobuster_output.splitlines():
                    match = re.match(r'^(/[^ ]+)', line.strip())
                    if match:
                        all_discovered_paths_raw.add(match.group(1))
            else:
                print(f"{RED}[!] One gobuster instance failed or had no output.{NC}")

    all_discovered_urls = set()
    for live_domain_url in live_domains_list:
        parsed_live_domain = urlparse(live_domain_url)
        base_url_for_paths = f"{parsed_live_domain.scheme}://{parsed_live_domain.netloc}"
        for path in all_discovered_paths_raw:
            full_url = urljoin(base_url_for_paths, path)
            all_discovered_urls.add(full_url)

    filtered_discovered_urls = filter_and_normalize_entries(all_discovered_urls, domain, entry_type="url")
    
    if filtered_discovered_urls:
        with open("discovered_paths.txt", "w") as f:
            f.write("\n".join(sorted(filtered_discovered_urls)))
        print(f"{GREEN}[+] All discovered URLs (from web content discovery) saved to discovered_paths.txt{NC}")
    else:
        print(f"{YELLOW}[!] No additional web content URLs found with gobuster.{NC}")


def vulnerability_scanning():
    """Performs basic vulnerability scanning with Nuclei."""
    print(f"{YELLOW}[+] Running vulnerability scanning with Nuclei...{NC}")
    if not os.path.exists("urls.txt") and not os.path.exists("domain.live"):
        print(f"{RED}[!] No URLs or live domains found. Skipping vulnerability scanning.{NC}")
        return
    
    target_file = "urls.txt" if os.path.exists("urls.txt") else "domain.live"

    nuclei_output_file = "nuclei_results.txt"
    nuclei_cmd = f"nuclei -l {target_file} -t {NUCLEI_TEMPLATES_PATH} -o {nuclei_output_file} -s low,medium,high,critical -silent -stats"
    
    if not Path(NUCLEI_TEMPLATES_PATH).exists():
        print(f"{RED}[!] Nuclei templates path not found: {NUCLEI_TEMPLATES_PATH}. Please ensure Nuclei templates are downloaded.{NC}")
        print(f"{YELLOW}    You can download them using: 'nuclei -update-templates'{NC}")
        return

    success, _ = run_command(nuclei_cmd, silent=False, check_install="nuclei")
    if success:
        print(f"{GREEN}[+] Nuclei scan completed. Results saved to {nuclei_output_file}.{NC}")
    else:
        print(f"{RED}[!] Failed to run Nuclei. Check installation or template path.{NC}")

def parameter_discovery(main_target_domain):
    """Identifies potential URL parameters using paramspider."""
    print(f"{YELLOW}[+] Running parameter discovery...{NC}")
    if not os.path.exists("urls.txt"):
        print(f"{RED}[!] urls.txt not found. Skipping parameter discovery.{NC}")
        return

    paramspider_output_file = "discovered_parameters_raw.txt"
    final_output_file = "discovered_parameters.txt"
    
    cmd = f"paramspider --domain-list urls.txt --output {paramspider_output_file}"
    
    print(f"{BLUE}[+] Running ParamSpider...{NC}")
    success, _ = run_command(cmd, silent=True, check_install="paramspider") 

    if success and os.path.exists(paramspider_output_file):
        all_params = set()
        with open(paramspider_output_file, 'r') as f:
            all_params.update(line.strip() for line in f if line.strip())
        os.remove(paramspider_output_file)

        filtered_params = filter_and_normalize_entries(all_params, main_target_domain, entry_type="url")
        
        if filtered_params:
            with open(final_output_file, "w") as f:
                f.write("\n".join(sorted(filtered_params)))
            print(f"{GREEN}[+] Parameter discovery completed. Results saved to {final_output_file}.{NC}")
        else:
            print(f"{YELLOW}[!] No parameters found or all filtered out.{NC}")
    else:
        print(f"{RED}[!] Failed to run ParamSpider or output not found. Ensure ParamSpider is installed and accessible.{NC}")
        print(f"{YELLOW}[!] Consider manually running 'cat urls.txt | unfurl --unique paths | sort -u' to get unique paths for manual parameter testing.{NC}")


def screenshot_websites():
    """Takes screenshots of live websites using httpx."""
    print(f"{YELLOW}[+] Taking screenshots of live websites with httpx...{NC}")
    if not os.path.exists("domain.live"):
        print(f"{RED}[!] domain.live not found. Skipping screenshotting.{NC}")
        return

    output_dir = "screenshots"
    Path(output_dir).mkdir(exist_ok=True)

    cmd = f"cat domain.live | httpx -silent -sr -srs {output_dir}"
    
    success, _ = run_command(cmd, silent=True, check_install="httpx")
    if success:
        print(f"{GREEN}[+] Screenshots saved to '{output_dir}' directory.{NC}")
    else:
        print(f"{RED}[!] Failed to take screenshots with httpx. Ensure httpx is installed and accessible.{NC}")


def js_secrets_and_endpoints_analysis():
    """Analyzes JavaScript files for secrets and additional endpoints using SecretFinder."""
    print(f"{YELLOW}[+] Analyzing JavaScript files for secrets and additional endpoints...{NC}")
    if not os.path.exists("js_endpoints.txt"):
        print(f"{RED}[!] js_endpoints.txt not found. Skipping JS secrets/endpoints analysis.{NC}")
        return

    js_files_to_analyze = []
    with open("js_endpoints.txt", "r") as f:
        js_files_to_analyze = [line.strip() for line in f if line.strip().endswith(".js")]

    if not js_files_to_analyze:
        print(f"{YELLOW}[!] No JavaScript files found in js_endpoints.txt for analysis.{NC}")
        return

    secrets_output_file = "js_secrets.txt"
    extracted_secrets = set()
    
    secretfinder_path = Path("/usr/local/bin/secretfinder")

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for js_url in js_files_to_analyze:
            temp_secret_file = f"temp_secret_{abs(hash(js_url))}.json"
            cmd = f"python3 {secretfinder_path} -i {js_url} -o {temp_secret_file}"
            print(f"{BLUE}[+] Running SecretFinder on {js_url}...{NC}")
            # Submit the command and store a future, check_install ensures tool is present before running
            futures.append(executor.submit(run_command, cmd, silent=True, check_install="secretfinder" if secretfinder_path.exists() else None))

        for future in futures:
            success, _ = future.result() # Wait for each SecretFinder command to complete
            if not success and secretfinder_path.exists(): # If command failed despite tool being present
                print(f"{RED}[!] One SecretFinder instance failed to execute.{NC}")
            elif not success and not secretfinder_path.exists(): # Tool not found, handled earlier but for completeness
                 pass # Message already printed by run_command

    for js_url in js_files_to_analyze:
        temp_secret_file = f"temp_secret_{abs(hash(js_url))}.json"
        if os.path.exists(temp_secret_file):
            try:
                with open(temp_secret_file, "r") as f:
                    secrets_data = json.load(f)
                    for entry in secrets_data:
                        extracted_secrets.add(json.dumps(entry, sort_keys=True))
                os.remove(temp_secret_file)
            except json.JSONDecodeError:
                print(f"{RED}[!] Failed to parse SecretFinder JSON from {temp_secret_file}. File might be empty or malformed.{NC}")
            except Exception as e:
                print(f"{RED}Error processing {temp_secret_file}: {e}{NC}")

    if extracted_secrets:
        with open(secrets_output_file, "w") as f:
            for secret in sorted(list(extracted_secrets)):
                f.write(secret + "\n")
        print(f"{GREEN}[+] Discovered secrets saved to {secrets_output_file}.{NC}")
    else:
        print(f"{YELLOW}[!] No secrets or sensitive data found in JavaScript files.{NC}")


def autorecon(project_name=None, domains=None, crawl=False, recursive=False, headers=None, threads=4, enable_all_recon=False, custom_wordlist=None,
              enable_crawler=False, crawler_max_pages=10, crawler_output_format='json', crawler_headless=False):
    """Main function to orchestrate the reconnaissance process."""
    print_banner()
    
    if not project_name:
        print(f"{RED}{BOLD}Error: Project name (-n) is required{NC}")
        return
    
    project_path = setup_project(project_name)
    
    # Install external tools if not found. These will only be installed once.
    install_external_python_tool("jslinks", "https://github.com/00xmora/jslinks.git", "jslinks.py", "jslinks")
    if enable_crawler:
        install_external_python_tool("crawler", "https://github.com/00xmora/crawler.git", "crawler.py", "crawler")


    if not domains and not crawl and not enable_all_recon:
        print(f"{YELLOW}[+] No domains (-d), crawling (--crawl), or all recon (--all-recon) requested. Nothing to do.{NC}")
        return
    
    if domains:
        if isinstance(domains, str):
            domains = [domains]
        
        for domain in domains:
            print(f"{CYAN}{BOLD}\n[+] Processing domain: {domain}{NC}")
            setup_domain_directory(project_path, domain)
            
            # Phase 1: Passive Subdomain Enumeration
            passive_subdomain_enum(domain, threads)
            
            # Phase 2: Live Domain Filtering
            filter_live_domains(domain)
            
            # Phase 3: Active Subdomain Enumeration (dnsrecon, ffuf) if requested
            if args.active or enable_all_recon:
                active_subdomain_enum(domain, custom_wordlist_path=custom_wordlist)
            
            # Phase 4: URL Discovery and Crawling
            if crawl or enable_all_recon:
                if os.path.exists("domain.live"):
                    with open("domain.live") as f:
                        domains_list = f.read().splitlines()
                    if domains_list:
                        crawl_urls(
                            domain, domains_list, recursive=recursive, headers=headers,
                            enable_crawler=enable_crawler,
                            crawler_max_pages=crawler_max_pages,
                            crawler_output_format=crawler_output_format,
                            crawler_headless=crawler_headless
                        )
                    else:
                        print(f"{YELLOW}[!] domain.live is empty, skipping crawling for {domain}.{NC}")
                else:
                    print(f"{RED}[!] domain.live not found, skipping crawling for {domain}.{NC}")
            
            # Phase 5: Port and Service Enumeration (only if IPs were found by httpx)
            if (args.ports_scan or enable_all_recon) and os.path.exists("ips.txt"):
                port_and_service_enum()

            # Phase 6: Web Content Discovery
            if (args.web_content_discovery or enable_all_recon) and os.path.exists("domain.live"):
                web_content_discovery(domain)
            
            # Phase 7: Parameter Discovery
            if (args.params_discovery or enable_all_recon) and os.path.exists("urls.txt"):
                parameter_discovery(domain)

            # Phase 8: Screenshot Websites
            if (args.screenshots or enable_all_recon) and os.path.exists("domain.live"):
                screenshot_websites()

            # Phase 9: JS Secrets and Endpoints Analysis
            if (args.js_analysis or enable_all_recon) and os.path.exists("js_endpoints.txt"):
                js_secrets_and_endpoints_analysis()
            
            # Phase 10: Vulnerability Scanning
            if (args.vuln_scan or enable_all_recon) and (os.path.exists("urls.txt") or os.path.exists("domain.live")):
                vulnerability_scanning()

            os.chdir(project_path)
    
    elif crawl:
        print(f"{YELLOW}[+] Crawling requested but no domains provided. Please provide domains with -d.{NC}")
    
    print(f"{GREEN}{BOLD}\n[+] All tasks completed. Results in '{project_name}' directory{NC}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoRecon in Python")
    parser.add_argument("-n", "--project-name", help="Project name", required=True)
    parser.add_argument("-d", "--domains", nargs="*", help="List of domains (e.g., example.com sub.example.org)")
    parser.add_argument("-w", "--wordlist", help="Path to a custom wordlist for DNS enumeration (dnsrecon) and FFUF (overrides default seclists wordlist)")
    parser.add_argument("--crawl", action="store_true", help="Enable URL discovery and crawling (waybackurls, katana, waymore, jslinks)")
    parser.add_argument("-active", action="store_true", help="Enable active subdomain enumeration (dnsrecon and ffuf)")
    parser.add_argument("-r", "--recursive", action="store_true", help="Enable recursive JS endpoint extraction (used with --crawl)")
    parser.add_argument("-H", "--header", action="append", help="Custom headers for HTTP requests (format: 'Header-Name: value')")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for concurrent execution (default: 10)")
    
    parser.add_argument("--all-recon", action="store_true", help="Enable all reconnaissance phases (active enum, crawl, ports, web content, params, screenshots, js analysis, vuln scan)")
    parser.add_argument("--ports-scan", action="store_true", help="Enable port and service enumeration with naabu and nmap")
    parser.add_argument("--web-content-discovery", action="store_true", help="Enable web content discovery (directory brute-forcing)")
    parser.add_argument("--params-discovery", action="store_true", help="Enable URL parameter discovery")
    parser.add_argument("--screenshots", action="store_true", help="Enable taking screenshots of live websites")
    parser.add_argument("--js-analysis", action="store_true", help="Enable analysis of JavaScript files for secrets and endpoints")
    parser.add_argument("--vuln-scan", action="store_true", help="Enable basic vulnerability scanning with Nuclei")

    # Arguments for crawler.py integration
    parser.add_argument("--enable-crawler", action="store_true", help="Enable dynamic crawling with crawler.py (requires manual login interaction)")
    parser.add_argument("--crawler-max-pages", type=int, default=10, help="Maximum number of pages for crawler.py to crawl (default: 10)")
    parser.add_argument("--crawler-output-format", choices=['json', 'txt', 'csv'], default='json', help="Output format for crawler.py (json, txt, csv). Note: AutoRecon processes JSON internally.")
    parser.add_argument("--crawler-headless", action="store_true", help="Run crawler.py in headless browser mode.")

    args = parser.parse_args()
    
    custom_headers = {}
    if args.header:
        for h in args.header:
            try:
                key, value = h.split(":", 1)
                custom_headers[key.strip()] = value.strip()
            except ValueError:
                print(f"{RED}❌ Invalid header format: {h} (should be 'Header-Name: value'){NC}")
                exit(1)
    
    autorecon(
        project_name=args.project_name,
        domains=args.domains,
        crawl=args.crawl,
        recursive=args.recursive,
        headers=custom_headers,
        threads=args.threads,
        enable_all_recon=args.all_recon,
        custom_wordlist=args.wordlist,
        enable_crawler=args.enable_crawler,
        crawler_max_pages=args.crawler_max_pages,
        crawler_output_format=args.crawler_output_format,
        crawler_headless=args.crawler_headless
    )