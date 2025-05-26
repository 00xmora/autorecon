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
        'dnsdumpster':'',
        'netcraft':'',
        'socradar':'',
        'shrewdeye':'',
        'chaos':'' # Added Chaos API key
    }
    # Add sections for tool configurations if they don't exist
    if 'TOOL_CONFIGS' not in config:
        config['TOOL_CONFIGS'] = {
            'subfinder_config': os.path.join(str(Path.home()), '.config', 'subfinder', 'config.yaml'),
            'amass_config': os.path.join(str(Path.home()), '.config', 'amass', 'config.ini'),
            'httpx_config': os.path.join(str(Path.home()), '.config', 'httpx', 'config.yaml'),
            'nuclei_templates_path': os.path.join(str(Path.home()), 'nuclei-templates'),
            'seclists_path': '/usr/share/seclists' # General seclists path
        }

    with open(config_file, 'w') as f:
        config.write(f)
    print(f"{YELLOW}[+] Created default config.ini. Please add your API keys and verify tool config paths if available.{NC}")

PENTEST_API_KEY = config['API_KEYS'].get('pentest_tools', '')
SECURITYTRAILS_API_KEY = config['API_KEYS'].get('securitytrails', '')
SHREUDEYE_API_KEY = config['API_KEYS'].get('shrewdeye', '')
CHAOS_API_KEY = config['API_KEYS'].get('chaos', '') # Get Chaos API key

# Tool config paths
SUBFINDER_CONFIG = config['TOOL_CONFIGS'].get('subfinder_config')
AMASS_CONFIG = config['TOOL_CONFIGS'].get('amass_config')
HTTPX_CONFIG = config['TOOL_CONFIGS'].get('httpx_config')
NUCLEI_TEMPLATES_PATH = config['TOOL_CONFIGS'].get('nuclei_templates_path')
SECLISTS_PATH = config['TOOL_CONFIGS'].get('seclists_path')

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
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, stderr=subprocess.DEVNULL)
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

def configure_tool_apikeys():
    print(f"{YELLOW}[+] Attempting to configure API keys for tools...{NC}")

    # Subfinder
    if SUBFINDER_CONFIG and (config['API_KEYS'].get('securitytrails') or config['API_KEYS'].get('chaos')):
        try:
            subfinder_config_path = Path(SUBFINDER_CONFIG)
            subfinder_config_path.parent.mkdir(parents=True, exist_ok=True)
            
            subfinder_config_content = ""
            if subfinder_config_path.exists():
                with open(subfinder_config_path, 'r') as f:
                    subfinder_config_content = f.read()
            else:
                subfinder_config_content = "providers:\n"

            if SECURITYTRAILS_API_KEY:
                if re.search(r'securitytrails:\s*""', subfinder_config_content):
                    subfinder_config_content = re.sub(r'securitytrails:\s*""', f'securitytrails: "{SECURITYTRAILS_API_KEY}"', subfinder_config_content)
                elif "securitytrails:" in subfinder_config_content:
                    subfinder_config_content = re.sub(r'securitytrails: ".+"', f'securitytrails: "{SECURITYTRAILS_API_KEY}"', subfinder_config_content)
                else:
                    subfinder_config_content += f'\n  securitytrails: "{SECURITYTRAILS_API_KEY}"'
                print(f"{GREEN}[+] Subfinder API key configured for SecurityTrails.{NC}")
            
            with open(subfinder_config_path, 'w') as f:
                f.write(subfinder_config_content)
        except Exception as e:
            print(f"{RED}[!] Error configuring Subfinder API key: {e}{NC}")
    else:
        print(f"{YELLOW}[!] Subfinder config path or relevant API keys not found, skipping Subfinder API configuration.{NC}")

    # Amass
    if AMASS_CONFIG and SECURITYTRAILS_API_KEY:
        try:
            amass_config_path = Path(AMASS_CONFIG)
            amass_config_path.parent.mkdir(parents=True, exist_ok=True)
            
            amass_config_content = ""
            if amass_config_path.exists():
                with open(amass_config_path, 'r') as f:
                    amass_config_content = f.read()
            else: # Create a basic Amass config if it doesn't exist
                amass_config_content = """# Amass Configuration
scope:
  domains: []
  ips: []
  asns: []
  cidrs: []
  ports: []
  blacklist: []
options:
  resolvers: []
  datasources: ""
  wordlist: []
  database: ""
  bruteforce:
    enabled: false
    wordlists: []
  alterations:
    enabled: false
    wordlists: []
"""
            # Use regex to find or add the SecurityTrails API key within the Amass config
            # Amass config uses a 'securitytrails' section under 'datasources'
            
            # First, ensure datasources section is present and correctly formatted if adding new
            # This is a simplified approach, a more robust parser would be needed for complex YAML/INI
            if "datasources:" not in amass_config_content:
                 # Find a suitable place to insert 'datasources:' if it's missing
                 # This is a heuristic; might need adjustment based on typical config structure
                if "options:" in amass_config_content:
                    amass_config_content = amass_config_content.replace("options:", "options:\n  datasources: ''")
                else: # Add at the end if no 'options' section
                    amass_config_content += "\noptions:\n  datasources: ''\n"

            # Now, handle the SecurityTrails API key within the datasources section
            # Check if a datasources.yaml is specified or if keys are inline
            # For this example, we'll assume a direct "securitytrails" entry within the main config
            
            # Simple approach: append or replace a 'securitytrails' entry in the datasources section
            # This might not be perfectly aligned with Amass's full datasource management,
            # but covers common API key integration.
            
            # Look for existing securitytrails key
            if re.search(r'securitytrails_apikey:\s*""', amass_config_content):
                amass_config_content = re.sub(r'securitytrails_apikey:\s*""', f'securitytrails_apikey: "{SECURITYTRAILS_API_KEY}"', amass_config_content)
            elif re.search(r'securitytrails_apikey:\s*".+"', amass_config_content):
                amass_config_content = re.sub(r'securitytrails_apikey:\s*".+"', f'securitytrails_apikey: "{SECURITYTRAILS_API_KEY}"', amass_config_content)
            else:
                # Add it if not found, ideally under a 'datasources' section or similar structure
                # A common place is directly under 'options' for many tools
                # Amass expects it under a 'data_sources' map in its config file structure (not just string values)
                # Example from Amass doc:
                # data_sources:
                #  securitytrails:
                #    apikey: xxx
                
                # This is more complex to add programmatically into an INI-like structure
                # A safer approach for Amass is to point to a datasources.yaml or tell user to do it.
                # Given the example config, it seems Amass expects a separate datasources.yaml file.
                # Let's pivot to creating/modifying a datasources.yaml if the config.ini refers to one.

                amass_config_obj = configparser.ConfigParser()
                amass_config_obj.read_string(amass_config_content)
                
                datasources_file = None
                if 'options' in amass_config_obj and 'datasources' in amass_config_obj['options']:
                    datasources_file = amass_config_obj['options']['datasources'].strip().strip('"\'')
                    if datasources_file and datasources_file != "./datasources.yaml": # If custom path set
                        print(f"{YELLOW}[!] Amass config points to a custom datasources file: {datasources_file}. Please configure SecurityTrails API key there manually.{NC}")
                        datasources_file = None # Don't try to auto-configure if it's a custom path
                
                if not datasources_file: # If no datasources file specified or it's default
                    # Default datasources.yaml location if not specified in main config.ini
                    datasources_file = amass_config_path.parent / "datasources.yaml"
                    
                if datasources_file:
                    try:
                        datasources_file_path = Path(datasources_file)
                        datasources_file_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        datasources_yaml_content = ""
                        if datasources_file_path.exists():
                            with open(datasources_file_path, 'r') as f:
                                datasources_yaml_content = f.read()
                        
                        # Add or update SecurityTrails API key in YAML format
                        if "securitytrails:" in datasources_yaml_content:
                            # Replace apikey if it exists
                            datasources_yaml_content = re.sub(r'(securitytrails:\s*\n\s*apikey:\s*)"[^"]*"', r'\1"{}"'.format(SECURITYTRAILS_API_KEY), datasources_yaml_content)
                        else:
                            # Add new securitytrails block
                            datasources_yaml_content += f"""
securitytrails:
  apikey: "{SECURITYTRAILS_API_KEY}"
"""
                        with open(datasources_file_path, 'w') as f:
                            f.write(datasources_yaml_content)
                        print(f"{GREEN}[+] Amass SecurityTrails API key configured in {datasources_file_path}.{NC}")
                    except Exception as e:
                        print(f"{RED}[!] Error configuring Amass SecurityTrails API key in datasources.yaml: {e}{NC}")
            
            with open(amass_config_path, 'w') as f:
                f.write(amass_config_content)
            
        except Exception as e:
            print(f"{RED}[!] Error configuring Amass API key: {e}{NC}")
    else:
        print(f"{YELLOW}[!] Amass config path or SecurityTrails API key not found, skipping Amass API configuration.{NC}")
    
def get_subdomains_from_free_services(target):
    subdomains = set()
    print(f"{YELLOW}[+] Fetching subdomains from various free services...{NC}")

    # 1. Pentest-Tools.com (API if key)
    if PENTEST_API_KEY:
        headers = {"X-API-Key": PENTEST_API_KEY}
        base_url = "https://pentest-tools.com/api"
        try:
            response = requests.post(f"{base_url}/targets", json={"name": target, "type": "domain"}, headers=headers, timeout=10)
            response.raise_for_status() # Raise an exception for bad status codes
            target_id = response.json().get("id")
            scan_data = {"target_id": target_id, "tool": "subdomain_finder"}
            response = requests.post(f"{base_url}/scans", json=scan_data, headers=headers, timeout=10)
            response.raise_for_status()
            scan_id = response.json().get("scan_id")
            print(f"{BLUE}[+] Pentest-Tools scan initiated (ID: {scan_id}), waiting for results...{NC}")
            while True:
                response = requests.get(f"{base_url}/scans/{scan_id}", headers=headers, timeout=10)
                response.raise_for_status()
                data = response.json()
                if data.get("status") == "finished":
                    subdomains.update(data.get("results", {}).get("subdomains", []))
                    print(f"{GREEN}[+] Retrieved subdomains from Pentest-Tools API.{NC}")
                    break
                elif data.get("status") == "error":
                    print(f"{RED}[!] Pentest-Tools scan failed with error: {data.get('error')}{NC}")
                    break
                time.sleep(10)
        except requests.exceptions.RequestException as e:
            print(f"{RED}Error with Pentest-Tools API: {e}{NC}")
        except Exception as e:
            print(f"{RED}Unexpected error with Pentest-Tools API: {e}{NC}")
    else:
        print(f"{YELLOW}[!] Pentest-Tools API key not provided. Skipping web retrieval due to potential CAPTCHA/changes.{NC}")

    # 2. DNSdumpster.com
    try:
        response = requests.get("https://dnsdumpster.com", timeout=15)
        response.raise_for_status()
        csrf_token_match = re.search(r'name="csrfmiddlewaretoken" value="(.+?)"', response.text)
        if not csrf_token_match:
            print(f"{RED}[!] Could not find CSRF token for DNSdumpster.{NC}")
            raise ValueError("CSRF token not found")
        csrf_token = csrf_token_match.group(1)
        data = {"csrfmiddlewaretoken": csrf_token, "targetip": target}
        headers = {"Referer": "https://dnsdumpster.com"}
        response = requests.post("https://dnsdumpster.com", data=data, headers=headers, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        for td in soup.select("td.col-md-4"):
            subdomain = td.text.strip()
            if subdomain.endswith(f".{target}") and subdomain != target:
                subdomains.add(subdomain)
        print(f"{GREEN}[+] Retrieved subdomains from DNSdumpster.com.{NC}")
    except requests.exceptions.RequestException as e:
        print(f"{RED}Error with DNSdumpster: {e}{NC}")
    except Exception as e:
        print(f"{RED}Unexpected error with DNSdumpster: {e}{NC}")

    # 3. SecurityTrails.com (API if key)
    if SECURITYTRAILS_API_KEY:
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        try:
            response = requests.get(f"https://api.securitytrails.com/v1/domain/{target}/subdomains", headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            for sub in data.get("subdomains", []):
                subdomains.add(f"{sub}.{target}")
            print(f"{GREEN}[+] Retrieved subdomains from SecurityTrails API.{NC}")
        except requests.exceptions.RequestException as e:
            print(f"{RED}Error with SecurityTrails: {e}{NC}")
        except Exception as e:
            print(f"{RED}Unexpected error with SecurityTrails API: {e}{NC}")

    # 4. Netcraft.com (Web Scraping - can be brittle)
    try:
        response = requests.get(f"https://searchdns.netcraft.com/?host=*.{target}", timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        for a in soup.select("a[href*='site=']"):
            href_match = re.search(r"site=([^&]+)", a["href"])
            if href_match:
                subdomain = href_match.group(1)
                if subdomain.endswith(f".{target}") and subdomain != target:
                    subdomains.add(subdomain)
        print(f"{GREEN}[+] Retrieved subdomains from Netcraft.com.{NC}")
    except requests.exceptions.RequestException as e:
        print(f"{RED}Error with Netcraft: {e}{NC}")
    except Exception as e:
        print(f"{RED}Unexpected error with Netcraft: {e}{NC}")

    # 5. SOCRadar
    try:
        response = requests.get(f"https://api.socradar.io/tools/subdomains?domain={target}", timeout=10)
        response.raise_for_status()
        data = response.json()
        subdomains.update(data.get("subdomains", []))
        print(f"{GREEN}[+] Retrieved subdomains from SOCRadar.{NC}")
    except requests.exceptions.RequestException as e:
        print(f"{RED}Error with SOCRadar (API might require authentication or be rate-limited): {e}{NC}")
    except Exception as e:
        print(f"{RED}Unexpected error with SOCRadar: {e}{NC}")

    # 6. ShrewdEye.app (API)
    if SHREUDEYE_API_KEY:
        headers = {"X-API-KEY": SHREUDEYE_API_KEY}
        base_url = f"https://shrewdeye.app/api/v1/domains/{target}/resources"
        page = 1
        total_pages = 1
        try:
            while page <= total_pages:
                params = {"page": page}
                response = requests.get(base_url, headers=headers, params=params, timeout=15)
                response.raise_for_status()
                data = response.json()
                
                total_pages = data.get("last_page", 1)
                
                for resource in data.get("data", []):
                    name = resource.get("name")
                    if name and name.endswith(f".{target}"):
                        subdomains.add(name)
                
                print(f"{BLUE}[+] Retrieved ShrewdEye page {page}/{total_pages}...{NC}")
                page += 1
                time.sleep(0.5)
            print(f"{GREEN}[+] Retrieved all subdomains from ShrewdEye.app.{NC}")
        except requests.exceptions.RequestException as e:
            print(f"{RED}Error with ShrewdEye.app API: {e}{NC}")
        except Exception as e:
            print(f"{RED}Unexpected error with ShrewdEye.app API: {e}{NC}")
    else:
        print(f"{YELLOW}[!] ShrewdEye API key not provided. Skipping ShrewdEye.app.{NC}")

    # 7. Chaos API
    if CHAOS_API_KEY:
        headers = {
            "Authorization": CHAOS_API_KEY,
            "Connection": "close"
        }
        chaos_url = f"https://dns.projectdiscovery.io/dns/{target}/subdomains"
        try:
            print(f"{BLUE}[+] Fetching subdomains from Chaos API...{NC}")
            response = requests.get(chaos_url, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            if "subdomains" in data:
                for sub in data["subdomains"]:
                    if sub.endswith(f".{target}") or sub == "*":
                        subdomains.add(sub)
                    elif not sub.endswith(target) and sub != "*":
                        subdomains.add(f"{sub}.{target}")
            print(f"{GREEN}[+] Retrieved {len(data.get('subdomains', []))} subdomains from Chaos API.{NC}")
        except requests.exceptions.RequestException as e:
            print(f"{RED}Error with Chaos API: {e}{NC}")
        except json.JSONDecodeError:
            print(f"{RED}[!] Failed to parse JSON from Chaos API. Response might be malformed.{NC}")
        except Exception as e:
            print(f"{RED}Unexpected error with Chaos API: {e}{NC}")
    else:
        print(f"{YELLOW}[!] Chaos API key not provided. Skipping Chaos API.{NC}")

    return subdomains

def passive_subdomain_enum(domain, threads=20):
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
    
    service_subdomains = get_subdomains_from_free_services(domain)
    all_subdomains.update(service_subdomains)

    if all_subdomains:
        with open("domains.txt", "w") as f:
            f.write("\n".join(sorted(all_subdomains)))
        print(f"{GREEN}[+] All passive subdomains collected and saved to domains.txt{NC}")
    else:
        print(f"{YELLOW}[!] No passive subdomains found.{NC}")

def filter_live_domains():
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
                with open("ips.txt", "w") as f:
                    f.write("\n".join(sorted(unique_ips)))
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
        
        # Determine wordlist to use
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
                # You might choose to continue without ffuf or exit
                wordlist_ffuf = None # Mark as not available
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

        if wordlist_ffuf: # Only run ffuf if wordlist is available
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

        if live_domains:
            with open("domain.live", "w") as f:
                f.write("\n".join(sorted(live_domains)))
            print(f"{GREEN}[+] All active subdomains collected and saved to domain.live{NC}")
        else:
            print(f"{YELLOW}[!] No active subdomains found after dnsrecon and ffuf.{NC}")
            
    except Exception as e:
        print(f"{RED}[!] Error in active subdomain enumeration: {e}{NC}")


def fetch_js_files(url, headers):
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        js_pattern = re.compile(r'src=["\'](.*?\.js.*?)["\']', re.IGNORECASE)
        return [urljoin(url, js_file) for js_file in js_pattern.findall(response.text)]
    except requests.exceptions.RequestException as e:
        print(f"{YELLOW}[+] Error fetching JS files from {url}: {e}{NC}")
        return []
    except Exception as e:
        print(f"{YELLOW}[+] An unexpected error occurred while fetching JS files from {url}: {e}{NC}")
        return []

def extract_endpoints(js_url, headers):
    patterns = [
        re.compile(r'https?:\/\/(?:[a-zA-Z0-9.-]+)\.[a-zA-Z0-9.-]+(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?'),
        re.compile(r'\/(?:api|v\d+|graphql|gql|rest|wp-json|endpoint|service|data|public|private|internal|external)(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?'),
        re.compile(r'(?<![\/\w])(?:api|v\d+|graphql|gql|rest|wp-json|endpoint|service|data|public|private|internal|external)(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?(?![a-zA-9_-])'),
        re.compile(r'(["\'])([a-zA-Z][a-zA-Z0-9_-]{2,}\/[a-zA-Z0-9_-]{2,}(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?)(\1)'),
        re.compile(r'(?:"[^"]*"|\'[^\']*\'|)(?<![\w\/])([a-zA-Z][a-zA-Z0-9_-]{1,}\/[a-zA-Z0-9_-]{2,}(?:\/[a-zA-Z0-9_-]+)*(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?)(?![\w-])'),
        re.compile(r'(?<!\/)([a-zA-Z][a-zA-Z0-9_-]*\.(?:php|asp|jsp|aspx|cfm|cgi|pl|py|rb|do|action))(?:\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+(?:&[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)*)?\b', re.IGNORECASE),
    ]
    try:
        response = requests.get(js_url, headers=headers, timeout=10)
        response.raise_for_status()
        endpoints = set()
        for pattern in patterns:
            matches = pattern.findall(response.text)
            if pattern.pattern.startswith(r'(["\'])'):
                endpoints.update(match[1] for match in matches)
            else:
                endpoints.update(matches)
        return endpoints
    except requests.exceptions.RequestException as e:
        print(f"{YELLOW}[+] Error extracting endpoints from {js_url}: {e}{NC}")
        return set()
    except Exception as e:
        print(f"{YELLOW}[+] An unexpected error occurred while extracting endpoints from {js_url}: {e}{NC}")
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
    print(f"{YELLOW}[+] Discovering JS files and extracting endpoints...{NC}")
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    }
    headers = headers if headers else default_headers
    
    urls_to_crawl = []
    for d in domains:
        if not d.startswith(('http://', 'https://')):
            urls_to_crawl.append(f"https://{d}")
        else:
            urls_to_crawl.append(d)
    
    found_endpoints = set()
    if os.path.exists(output):
        try:
            with open(output, "r") as f:
                found_endpoints.update(line.strip() for line in f if line.strip())
        except Exception as e:
            print(f"{RED}[!] Error reading existing {output}: {e}{NC}")
    
    visited_js = set()
    queue = list(urls_to_crawl)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_js_files, url, headers): url for url in urls_to_crawl}
        
        while futures:
            done, _ = ThreadPoolExecutor().wait(futures, timeout=5)
            
            for future in done:
                url_processed = futures.pop(future)
                js_files_found = future.result()
                
                for js_url in js_files_found:
                    if js_url not in visited_js:
                        visited_js.add(js_url)
                        
                        extract_future = executor.submit(extract_endpoints, js_url, headers)
                        extract_future.add_done_callback(
                            lambda f: found_endpoints.update({normalize_endpoint(ep, js_url) for ep in f.result()})
                        )
                        if recursive and js_url not in queue:
                            queue.append(js_url)

            new_urls_to_process = [u for u in queue if u not in {f.url for f in futures.keys()}]
            for u in new_urls_to_process:
                futures[executor.submit(fetch_js_files, u, headers)] = u
                queue.remove(u)

            if not futures and not queue:
                break
            
            time.sleep(0.5)

    with open(output, "w") as f:
        f.write("\n".join(sorted(found_endpoints)))
    print(f"{GREEN}[+] JS endpoints saved to {output} (sorted and deduplicated){NC}")
    
    return list(found_endpoints)

def crawl_urls(domain, domains_list, recursive=False, headers=None):
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
    
    jslinks(domains=domains_list, output="js_endpoints.txt", recursive=recursive, headers=headers)
    
    all_urls = set()
    for file in ["wayback.txt", "katana.txt", "waymore.txt", "waybackrobots.txt", "js_endpoints.txt"]:
        if os.path.exists(file):
            with open(file, 'r', errors='ignore') as f:
                all_urls.update(line.strip() for line in f if line.strip())
    
    domain_pattern = re.compile(rf'https?://(?:[a-zA-Z0-9-]+\.)*{re.escape(domain)}(?:/|$|\?)', re.IGNORECASE)
    filtered_urls = {url for url in all_urls if domain_pattern.match(url)}
    
    with open("urls.txt", "w") as f:
        f.write("\n".join(sorted(filtered_urls)))
    
    for file in ["wayback.txt", "katana.txt", "waymore.txt", "waybackrobots.txt", "js_endpoints.txt", temp_domains_file]:
        if os.path.exists(file):
            os.remove(file)
    print(f"{GREEN}[+] URL discovery and crawling completed (sorted and deduplicated, filtered for {domain}){NC}")

def port_and_service_enum():
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
            output_file = f"gobuster_output_{d.replace('://', '_').replace('/', '_')}.txt"
            cmd = f"gobuster dir -u {d} -w {wordlist} -o {output_file} -t 50 -k" 
            print(f"{BLUE}[+] Running gobuster on {d}...{NC}")
            gobuster_futures.append(executor.submit(run_command, cmd, silent=True, check_install="gobuster"))
    
        for future in gobuster_futures:
            success, _ = future.result()
            if not success:
                print(f"{RED}[!] One gobuster instance failed.{NC}")

    all_discovered_paths = set()
    for d in live_domains_list:
        output_file = f"gobuster_output_{d.replace('://', '_').replace('/', '_')}.txt"
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    all_discovered_paths.update(line.strip() for line in f if line.strip().startswith('/'))
                os.remove(output_file)
            except Exception as e:
                print(f"{RED}Error processing {output_file}: {e}{NC}")
    
    if all_discovered_paths:
        with open("discovered_paths.txt", "w") as f:
            f.write("\n".join(sorted(all_discovered_paths)))
        print(f"{GREEN}[+] All discovered paths saved to discovered_paths.txt{NC}")
    else:
        print(f"{YELLOW}[!] No additional web content paths found with gobuster.{NC}")


def vulnerability_scanning():
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

def parameter_discovery():
    print(f"{YELLOW}[+] Running parameter discovery...{NC}")
    if not os.path.exists("urls.txt"):
        print(f"{RED}[!] urls.txt not found. Skipping parameter discovery.{NC}")
        return

    paramspider_output_file = "discovered_parameters.txt"
    
    cmd = f"paramspider --domain-list urls.txt --output {paramspider_output_file}"
    
    print(f"{BLUE}[+] Running ParamSpider...{NC}")
    success, _ = run_command(cmd, silent=True, check_install="paramspider") 

    if success and os.path.exists(paramspider_output_file):
        print(f"{GREEN}[+] Parameter discovery completed. Results saved to {paramspider_output_file}.{NC}")
    else:
        print(f"{RED}[!] Failed to run ParamSpider or output not found. Ensure ParamSpider is installed and accessible.{NC}")
        print(f"{YELLOW}[!] Consider manually running 'cat urls.txt | unfurl --unique paths | sort -u' to get unique paths for manual parameter testing.{NC}")


def screenshot_websites():
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
    
    secretfinder_path = Path("/usr/local/bin/secretfinder") # Assuming it's symlinked here
    if not secretfinder_path.exists():
        print(f"{RED}[!] SecretFinder (symlink) not found at {secretfinder_path}. Skipping secret analysis.{NC}")
        print(f"{YELLOW}    Please ensure SecretFinder is installed and symlinked as 'secretfinder' in /usr/local/bin.{NC}")
        return

    secret_futures = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        for js_url in js_files_to_analyze:
            temp_secret_file = f"temp_secret_{abs(hash(js_url))}.json" # Use abs(hash) to ensure positive filename
            # Note: SecretFinder's -o expects a path, it creates the file.
            cmd = f"python3 {secretfinder_path} -i {js_url} -o {temp_secret_file}"
            print(f"{BLUE}[+] Running SecretFinder on {js_url}...{NC}")
            secret_futures.append(executor.submit(run_command, cmd, silent=True))

        for future in secret_futures:
            success, _ = future.result()
            if not success:
                print(f"{RED}[!] One SecretFinder instance failed.{NC}")

    for js_url in js_files_to_analyze:
        temp_secret_file = f"temp_secret_{abs(hash(js_url))}.json"
        if os.path.exists(temp_secret_file):
            try:
                with open(temp_secret_file, "r") as f:
                    secrets_data = json.load(f)
                    for entry in secrets_data:
                        extracted_secrets.add(json.dumps(entry))
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


def autorecon(project_name=None, domains=None, crawl=False, recursive=False, headers=None, threads=4, enable_all_recon=False, custom_wordlist=None):
    print_banner()
    
    if not project_name:
        print(f"{RED}{BOLD}Error: Project name (-n) is required{NC}")
        return
    
    project_path = setup_project(project_name)
    
    configure_tool_apikeys()

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
            filter_live_domains()
            
            # Phase 3: Active Subdomain Enumeration (dnsrecon, ffuf) if requested
            if args.active or enable_all_recon:
                active_subdomain_enum(domain, custom_wordlist_path=custom_wordlist) # Pass custom wordlist
            
            # Phase 4: URL Discovery and Crawling
            if crawl or enable_all_recon:
                if os.path.exists("domain.live"):
                    with open("domain.live") as f:
                        domains_list = f.read().splitlines()
                    if domains_list:
                        crawl_urls(domain, domains_list, recursive=recursive, headers=headers)
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
                parameter_discovery()

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
    import argparse
    parser = argparse.ArgumentParser(description="AutoRecon in Python")
    parser.add_argument("-n", "--project-name", help="Project name", required=True)
    parser.add_argument("-d", "--domains", nargs="*", help="List of domains (e.g., example.com sub.example.org)")
    parser.add_argument("-w", "--wordlist", help="Path to a custom wordlist for DNS enumeration (dnsrecon) and FFUF (overrides default seclists wordlist)") # New wordlist arg
    parser.add_argument("--crawl", action="store_true", help="Enable URL discovery and crawling (waybackurls, katana, waymore, jslinks)")
    parser.add_argument("-active", action="store_true", help="Enable active subdomain enumeration (dnsrecon and ffuf)")
    parser.add_argument("-r", "--recursive", action="store_true", help="Enable recursive JS crawling (used with --crawl)")
    parser.add_argument("-H", "--header", action="append", help="Custom headers for HTTP requests (format: 'Header-Name: value')")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for concurrent execution (default: 10)")
    
    # New arguments for additional automation
    parser.add_argument("--all-recon", action="store_true", help="Enable all reconnaissance phases (active enum, crawl, ports, web content, params, screenshots, js analysis, vuln scan)")
    parser.add_argument("--ports-scan", action="store_true", help="Enable port and service enumeration with naabu and nmap")
    parser.add_argument("--web-content-discovery", action="store_true", help="Enable web content discovery (directory brute-forcing)")
    parser.add_argument("--params-discovery", action="store_true", help="Enable URL parameter discovery")
    parser.add_argument("--screenshots", action="store_true", help="Enable taking screenshots of live websites")
    parser.add_argument("--js-analysis", action="store_true", help="Enable analysis of JavaScript files for secrets and endpoints")
    parser.add_argument("--vuln-scan", action="store_true", help="Enable basic vulnerability scanning with Nuclei")

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
        custom_wordlist=args.wordlist # Pass custom wordlist
    )