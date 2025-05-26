# AutoRecon

AutoRecon is a powerful automated reconnaissance tool designed to simplify and streamline the process of subdomain enumeration, URL discovery, web content analysis, and initial vulnerability scanning. It orchestrates a suite of popular open-source tools and integrates with various online services (both free and API-based) to provide a comprehensive and organized workflow.

## Features

### Subdomain Enumeration:
- **Passive Enumeration:** Leverages tools like `amass`, `subfinder`, `sublist3r`, and integrates with online services such as Pentest-Tools.com, DNSdumpster.com, SecurityTrails.com, Netcraft.com, SOCRadar, ShrewdEye.app, and **Chaos API**.
- **Active Enumeration:** Performs DNS brute-forcing with `dnsrecon` and virtual host enumeration with `ffuf`.

### Live Domain Filtering:
- Filters discovered domains to identify live and responsive web servers using `httpx`, also extracting associated IP addresses for further scanning.

### URL Discovery & JavaScript Analysis:
- Discovers URLs from various sources using `waybackurls`, `katana`, `waymore`, and `waybackrobots`.
- Extracts JavaScript files from discovered URLs.
- Analyzes JavaScript files for potential endpoints and sensitive information (e.g., API keys, credentials) using tools like `SecretFinder`.

### Web Content Discovery:
- Performs directory and file brute-forcing on live web servers using `gobuster` to uncover hidden paths and resources.

### Port & Service Enumeration:
- Conducts fast port scanning with `naabu` and performs detailed service version detection and basic vulnerability scanning with `nmap` on identified open ports.

### Parameter Discovery:
- Identifies potential URL parameters using `paramspider` to aid in further testing.

### Visual Reconnaissance:
- Automatically takes screenshots of all live websites using `httpx` for quick visual assessment.

### Vulnerability Scanning:
- Performs initial vulnerability scanning using `nuclei` with community-contributed templates.

### Organized Output:
- Saves all results in a structured directory for each domain, with sorted and deduplicated files for easy analysis.

## Installation

### Prerequisites
- **Linux-based system** (e.g., Ubuntu, Debian, Kali Linux).
- **Python 3** and `pip` installed.
- **Go** (Golang) installed for Go-based tools (version 1.16+ recommended).
- **Basic system packages**: `git`, `curl`, `wget`, `unzip`, `dnsutils`.

### Installation Steps
1.  **Clone the repository**:
    ```bash
    git clone [https://github.com/00xmora/autorecon.git](https://github.com/00xmora/autorecon.git)
    cd autorecon
    ```
2.  **Make the installation script executable**:
    ```bash
    chmod +x install.sh
    ```
3.  **Run the installation script**:
    ```bash
    ./install.sh
    ```
    This script will:
    - Update package lists and install system dependencies.
    - Install `pipx` for managing Python applications.
    - Install Go-based tools (`amass`, `subfinder`, `httpx`, `waybackurls`, `katana`, `waybackrobots`, `ffuf`, `naabu`, `nuclei`, `gobuster`).
    - Install Python-based tools (`sublist3r`, `dnsrecon`, `paramspider`, `SecretFinder`) by cloning their repositories and handling dependencies.
    - Install `seclists` (if not already installed).
    - Update Nuclei templates.
    - Move `autorecon.py` to `/usr/local/bin/autorecon` and `config.ini` to `/usr/local/bin/config.ini` for global access.

**Important Post-Installation Steps:**
- **Restart your terminal** or run `source ~/.bashrc` (or `~/.profile`) to ensure your PATH is updated and newly installed tools are found.
- **Edit the `config.ini` file** located at `/usr/local/bin/config.ini` to add your API keys for services like Pentest-Tools, SecurityTrails, ShrewdEye, and **Chaos API**. This is crucial for full functionality.

## Usage

Run `autorecon` with a project name and one or more domains. You can enable specific reconnaissance phases using the provided options, or run `all-recon` for a comprehensive scan.

```bash
autorecon -n MyProject -d example.com example2.com
````

### Options

  - `-n, --project-name <name>`: **(Required)** The name of the project directory where results will be saved.

  - `-d, --domains <domain1> [domain2 ...]`: One or more target domains to perform reconnaissance on.

  - `-w, --wordlist <path>`: Path to a custom wordlist for DNS enumeration (dnsrecon) and FFUF. Overrides the default Seclists wordlist.

  - `--crawl`: Enable URL discovery and crawling (waybackurls, katana, waymore, jslinks).

  - `-active`: Enable active subdomain enumeration (dnsrecon and ffuf).

  - `-r, --recursive`: Enable recursive JS endpoint extraction (used with `--crawl`).

  - `-H, --header <"Header-Name: value">`: Custom headers for HTTP requests (e.g., for JS crawling or web content discovery). Can be specified multiple times.

  - `-t, --threads <num>`: Number of threads for concurrent execution of tools (default: 10).

  - `--all-recon`: **Enable all reconnaissance phases**: active enumeration, URL crawling, port scanning, web content discovery, parameter discovery, screenshots, JS analysis, and vulnerability scanning.

  - `--ports-scan`: Enable port and service enumeration with `naabu` and `nmap`.

  - `--web-content-discovery`: Enable web content discovery (directory brute-forcing with `gobuster`).

  - `--params-discovery`: Enable URL parameter discovery with `paramspider`.

  - `--screenshots`: Enable taking screenshots of live websites with `httpx`.

  - `--js-analysis`: Enable analysis of JavaScript files for secrets and additional endpoints.

  - `--vuln-scan`: Enable basic vulnerability scanning with `nuclei`.

## Docker Usage

You can also run AutoRecon using Docker to ensure a consistent environment without manual dependency installation.

### 1\. Build the Docker Image

Navigate to the root directory of your AutoRecon project (where `Dockerfile`, `autorecon.py`, and `config.ini` are located) and build the image:

```bash
docker build -t autorecon .
```

### 2\. Prepare `config.ini` for Docker

Before running the container, ensure your `config.ini` file (in your local project directory) contains all the necessary API keys. This file will be mounted into the container.

### 3\. Run the Docker Container

When running the Docker container, you'll need to mount a local directory to store the reconnaissance results and also mount your `config.ini` file so the tool can access your API keys.

```bash
docker run -it --rm \
    -v "$(pwd)/my_recon_data:/app/my_recon_data" \
    -v "$(pwd)/config.ini:/usr/local/bin/config.ini" \
    autorecon -n my_project -d example.com --all-recon
```

  - `-it`: Runs the container in interactive mode and allocates a pseudo-TTY.
  - `--rm`: Automatically removes the container when it exits.
  - `-v "$(pwd)/my_recon_data:/app/my_recon_data"`: **Mounts a local directory** (e.g., `my_recon_data` in your current working directory) to `/app/my_recon_data` inside the container. All output files will be saved here, allowing you to access them after the container finishes.
  - `-v "$(pwd)/config.ini:/usr/local/bin/config.ini"`: **Mounts your local `config.ini` file** into the container, ensuring your API keys are used. Make sure this local `config.ini` has your API keys filled in.
  - `autorecon -n my_project -d example.com --all-recon`: The `autorecon` command with your desired arguments.

**Example Docker Run:**
To run a full reconnaissance on `target.com` and save results to a local `recon_output` folder:

```bash
mkdir recon_output # Create the local directory first
docker run -it --rm \
    -v "$(pwd)/recon_output:/app/my_recon_data" \
    -v "$(pwd)/config.ini:/usr/local/bin/config.ini" \
    autorecon -n target_scan -d target.com --all-recon
```


## Output

Results are saved in a structured directory for each domain within your specified project name:

```
MyProject/
├── [example.com/](https://example.com/)
│   ├── domains.txt            # All discovered passive subdomains
│   ├── domain.live            # Live/responsive subdomains
│   ├── ips.txt                # Unique IPs resolved from live domains
│   ├── urls.txt               # All discovered URLs (from crawling and JS analysis)
│   ├── js_endpoints.txt       # URLs of JavaScript files found
│   ├── js_secrets.txt         # Discovered secrets/sensitive data from JS files
│   ├── discovered_paths.txt   # Paths found via web content discovery
│   ├── naabu_open_ports.txt   # Open ports identified by naabu
│   ├── nmap_detailed_scan.xml # Detailed Nmap scan results (XML)
│   ├── discovered_parameters.txt # Discovered URL parameters
│   ├── nuclei_results.txt     # Vulnerability scan results from Nuclei
│   └── screenshots/           # Directory containing website screenshots
└── [example2.com/](https://example2.com/)
    └── ... (similar structure)
```

## Example Usage

Run a full reconnaissance scan on `example.com` and `test.com` with custom headers:

```bash
autorecon -n MyFullScan -d example.com test.com --all-recon -H "X-Custom-Header: value"
```

Run passive subdomain enumeration and URL crawling with recursive JS analysis and a custom wordlist:

```bash
autorecon -n MyProject -d target.com --crawl -r -w /opt/custom_wordlist.txt
```

## Contributing

Contributions are welcome\! To contribute:

1.  Fork the repository.
2.  Create a new branch for your feature or bugfix.
3.  Commit your changes.
4.  Submit a pull request.

## Acknowledgments

Thanks to the developers of the integrated tools: `amass`, `subfinder`, `sublist3r`, `httpx`, `ffuf`, `waybackurls`, `katana`, `waymore`, `uro`, `waybackrobots`, `naabu`, `nuclei`, `gobuster`, `paramspider`, `SecretFinder`, and the API services utilized (Pentest-Tools.com, DNSdumpster.com, SecurityTrails.com, Netcraft.com, SOCRadar, ShrewdEye.app, Chaos API).

## Contact
For questions, feedback, or support:
- X ( Formly Twitter): [@00xmora](https://x.com/00xmora)
- Linkedin: [@00xmora](https://www.linkedin.com/in/00xmora)

Enjoy using AutoRecon\! 🚀
