# AutoRecon

AutoRecon is a powerful automated reconnaissance tool designed to simplify and streamline the process of subdomain enumeration, URL discovery, web content analysis, and initial vulnerability scanning. This simplified version focuses on core tool orchestration, removing direct API key management for a leaner setup. It intelligently integrates with essential open-source tools to provide a comprehensive and organized workflow.

## Features

### Subdomain Enumeration:
- **Passive Enumeration:** Leverages tools like `amass`, `subfinder`, and `sublist3r`.
- **Active Enumeration:** Performs DNS brute-forcing with `dnsrecon` and virtual host enumeration with `ffuf`.

### Live Domain Filtering:
- Filters discovered domains to identify live and responsive web servers using `httpx`, also extracting associated IP addresses for further scanning.

### URL Discovery & JavaScript Analysis:
- Discovers URLs from various sources using `waybackurls`, `katana`, `waymore`, and `waybackrobots`.
- **Integrates `jslinks`**: Automatically extracts JavaScript files and analyzes them for potential endpoints.
- Analyzes JavaScript files for sensitive information (e.g., API keys, credentials) using `SecretFinder`.
- **Integrates `crawler`**: Optionally performs dynamic, interactive web crawling to discover more endpoints and requests.

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
- **Browser Drivers for `crawler.py`**: If using the `--enable-crawler` option, you will need Chrome or Firefox and their respective WebDriver installed and in your PATH. `chrome-driver` or `geckodriver`.

### Installation Steps

1.  **Clone the AutoRecon repository**:
    ```bash
    git clone [https://github.com/00xmora/autorecon.git](https://github.com/00xmora/autorecon.git)
    cd autorecon
    ```

2.  **Install core dependencies**:
    Most reconnaissance tools (`amass`, `subfinder`, `httpx`, `nuclei`, etc.) are installed via the provided `install.sh` script. Run this first:
    ```bash
    chmod +x install.sh
    ./install.sh
    ```
    This script handles the installation of common tools and sets up basic paths.

3.  **Run `autorecon.py`**:
    The `autorecon.py` script itself will handle the installation of `jslinks` and `crawler` (if `--enable-crawler` is used) on its first run if they are not detected in your system's PATH. It will clone their respective repositories from GitHub, install Python dependencies, and create necessary symlinks in `/usr/local/bin/`.

### Docker Usage

You can run AutoRecon using Docker to ensure a consistent environment without manually installing all dependencies.

**Important Note for `crawler.py`**: If you intend to use the `--enable-crawler` option, `crawler.py` will attempt to launch a browser for manual login. This means the Docker container needs access to a display server (X server) if not running in `--crawler-headless` mode. For most use cases within Docker, `--crawler-headless` is recommended. The Dockerfile below includes necessary browser dependencies.

#### 1. Build the Docker Image

Navigate to the directory containing your `autorecon.py` (and the `Dockerfile` you've created from the snippet above) and build the image:

```bash
docker build -t autorecon .
````

#### 2\. Run the Docker Container

When running the Docker container, you'll need to mount a local directory to store the reconnaissance results. `autorecon.py` no longer uses a `config.ini` file, as API key integration has been removed, and `jslinks` and `crawler` are self-installed by the script inside the container.

```bash
docker run -it --rm \
    -v "$(pwd)/my_recon_data:/app/output" \
    autorecon -n my_project -d example.com --all-recon --enable-crawler --crawler-headless
```

  - `-it`: Runs the container in interactive mode and allocates a pseudo-TTY.
  - `--rm`: Automatically removes the container when it exits.
  - `-v "$(pwd)/my_recon_data:/app/output"`: **Mounts a local directory** (e.g., `my_recon_data` in your current working directory) to `/app/output` inside the container. All output files will be saved here, allowing you to access them after the container finishes.
      * **Note**: Replace `my_recon_data` with your desired local directory name. `autorecon` will create project directories inside this mounted volume.
  - `autorecon -n my_project -d example.com --all-recon --enable-crawler --crawler-headless`: The `autorecon` command with your desired arguments.
      * If you enable `--enable-crawler`, it's highly recommended to also use `--crawler-headless` for non-interactive Docker environments.

**Example Docker Run:**
To run a full reconnaissance on `target.com` with dynamic crawling in headless mode and save results to a local `recon_output` folder:

```bash
mkdir recon_output # Create the local directory first
docker run -it --rm \
    -v "$(pwd)/recon_output:/app/output" \
    autorecon -n target_scan -d target.com --all-recon --enable-crawler --crawler-headless
```

### Important Post-Installation Steps:
- **Restart your terminal** or run `source ~/.bashrc` (or `~/.profile`) to ensure your PATH is updated and newly installed tools are found.

## Usage

Run `autorecon.py` with a project name and one or more domains. You can enable specific reconnaissance phases using the provided options, or run `--all-recon` for a comprehensive scan.

```bash
./autorecon.py -n MyProject -d example.com example2.com
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

#### `crawler.py` Specific Options (for dynamic crawling)

  - `--enable-crawler`: Enable dynamic crawling with `crawler.py`. **Note: This requires manual login interaction in the opened browser window.**
  - `--crawler-max-pages <num>`: Maximum number of pages for `crawler.py` to crawl (default: 10).
  - `--crawler-output-format <format>`: Output format for `crawler.py` (`json`, `txt`, `csv`). AutoRecon primarily processes JSON internally.
  - `--crawler-headless`: Run `crawler.py` in headless browser mode (no GUI).

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

  * **Run a full reconnaissance scan on `example.com` and `test.com` with custom headers**:

    ```bash
    ./autorecon.py -n MyFullScan -d example.com test.com --all-recon -H "User-Agent: MyReconTool/1.0"
    ```

  * **Run passive subdomain enumeration and URL crawling with recursive JS analysis and a custom wordlist**:

    ```bash
    ./autorecon.py -n MyProject -d target.com --crawl -r -w /opt/custom_wordlist.txt
    ```

  * **Run dynamic crawling on `example.com` in headless mode, allowing for manual login**:

    ```bash
    ./autorecon.py -n DynamicCrawlTest -d example.com --enable-crawler --crawler-headless
    ```

## Contributing

Contributions are welcome\! To contribute:

1.  Fork the repository.
2.  Create a new branch for your feature or bugfix.
3.  Commit your changes.
4.  Submit a pull request.

## Acknowledgments

Thanks to the developers of the integrated tools: `amass`, `subfinder`, `sublist3r`, `httpx`, `ffuf`, `waybackurls`, `katana`, `waymore`, `uro`, `waybackrobots`, `naabu`, `nuclei`, `gobuster`, `paramspider`, `SecretFinder`, [jslinks](https://github.com/00xmora/jslinks), and [crawler](https://github.com/00xmora/crawler).

## Contact

For questions, feedback, or support:

  - X (Formerly Twitter): [@00xmora](https://x.com/00xmora)
  - Linkedin: [@00xmora](https://www.linkedin.com/in/00xmora)

Enjoy using AutoRecon\! 🚀