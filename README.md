# AutoRecon

AutoRecon is a powerful automated reconnaissance tool designed to simplify the process of subdomain enumeration and URL discovery. It integrates multiple tools like `amass`, `subfinder`, `sublist3r`, `httpx`, `ffuf`, `waybackurls`, `katana`, `waymore`, `uro`, and `waybackrobots` to provide a comprehensive workflow, including JavaScript endpoint extraction.

## Features

### Subdomain Enumeration:
- Passive enumeration using `amass`, `subfinder`, and `sublist3r`.
- Active enumeration using `ffuf`.

### Live Domain Filtering:
- Filters live domains using `httpx`.

### URL Discovery:
- Discovers URLs using `waybackurls`, `katana`, `waymore`, and `waybackrobots`.
- Extracts JavaScript endpoints from discovered domains.

### Organized Output:
- Saves results in a structured directory for each domain, with sorted and deduplicated files.

## Installation

### Prerequisites
- Linux-based system (e.g., Ubuntu, Debian, Kali Linux).
- Python 3 and `pip` installed.
- Go installed for tools like `subfinder`, `httpx`, and `ffuf`.

### Installation Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/omarsamy10/autorecon.git
   cd autorecon
   ```
2. Make the installation script executable:
   ```bash
   chmod +x install.sh
   ```
3. Run the installation script:
   ```bash
   ./install.sh
   ```
   This installs all required tools and moves `autorecon` to `/usr/local/bin` for global access.

## Usage
Run `autorecon` with a project name and one or more domains:
```bash
autorecon -n MyProject -d example.com example2.com
```

### Options
- `-n, --project-name`: The name of the project directory where results will be saved (required).
- `-d, --domains`: One or more domains to perform reconnaissance on.
- `-c, --crawl`: Enable URL discovery and crawling (including JS endpoints).
- `-r, --recursive`: Enable recursive JS endpoint extraction.
- `-H, --header`: Custom headers for JS crawling (e.g., `"Authorization: Bearer token"`).

## Output
Results are saved in the following directory structure:
```
MyProject/
├── example.com/
│   ├── domains.txt       # Passive subdomain results
│   ├── domain.live      # Live domains
│   ├── domains          # Final subdomain list
│   ├── urls.txt         # Sorted, deduplicated URLs from all tools
└── example2.com/
    └── ...
```

## Example
```bash
autorecon -n MyProject -d example.com -c -r -H "User-Agent: CustomAgent"
```
### Output
```
[+] Project directory created: MyProject
[+] Processing domain: example.com
[+] Directory created: MyProject/example.com
[+] Running passive subdomain enumeration...
[+] Passive subdomain enumeration completed
[+] Filtering live domains...
[+] Live domains filtered
[+] Running active subdomain enumeration...
[+] Active subdomain enumeration completed
[+] Running URL discovery and crawling...
[+] JS endpoints saved to js_endpoints.txt (sorted and deduplicated)
[+] URL discovery and crawling completed (sorted and deduplicated)
[+] All tasks completed. Results in 'MyProject' directory
```

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes.
4. Submit a pull request.

## Acknowledgments
Thanks to the developers of the integrated tools: `amass`, `subfinder`, `sublist3r`, `httpx`, `ffuf`, `waybackurls`, `katana`, `waymore`, `uro`, and `waybackrobots`.

## Contact
For questions, feedback, or support:
- Twitter: [@omarsamy10](https://twitter.com/omarsamy10)
- Linkedin: [omarsamy](https://www.linkedin.com/in/omar-samy-2b34b3311)

Enjoy using AutoRecon! 🚀


#### Changes Made:
1. **Updated Tools List**: Included all tools from the current `autorecon.py`, including `uro` and JS endpoint extraction.
2. **Installation**: Updated to reflect the new `install.sh` behavior (global install).
3. **Usage**: Changed to use the global `autorecon` command and added all options (`-c`, `-r`, `-H`).
4. **Output**: Simplified to match the current script’s output files, removing unused ones like `amass.txt`.

