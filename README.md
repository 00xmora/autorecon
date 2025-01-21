AutoRecon
AutoRecon is a powerful automated reconnaissance tool designed to simplify the process of subdomain enumeration, URL discovery, and website inspection. It integrates multiple tools like amass, subfinder, sublist3r, httpx, ffuf, waybackurls, katana, waymore, crawley, and aquatone to provide a comprehensive reconnaissance workflow.

Features
Subdomain Enumeration:

Passive enumeration using amass, subfinder, and sublist3r.

Active enumeration using ffuf.

Live Domain Filtering:

Filters live domains using httpx.

URL Discovery:

Discovers URLs using waybackurls, katana, waymore, and crawley.

Visual Inspection:

Inspects results using aquatone.

Parallel Execution:

Runs multiple tools in parallel for faster results.

Organized Output:

Saves results in a structured directory for each domain.

Installation
Prerequisites
Linux-based system (e.g., Ubuntu, Debian, Kali Linux).

Python 3 and pip installed.

Go installed for tools like subfinder, httpx, and ffuf.

Installation Steps
Clone the repository:

bash
Copy
git clone https://github.com/yourusername/autorecon.git
cd autorecon
Make the installation script executable:

bash
Copy
chmod +x install_tools.sh
Run the installation script:

bash
Copy
./install_tools.sh
This script will install all the required tools and dependencies.

Usage
Basic Usage
Run the autorecon.sh script with a project name and one or more domains:

bash
Copy
./autorecon.sh MyProject domain1.com domain2.com
Output
The results will be saved in the following directory structure:

Copy
MyProject/
├── domain1.com/
│   ├── amass.txt
│   ├── subfinder.txt
│   ├── sublist3r.txt
│   ├── domains.txt
│   ├── domain.live
│   ├── ffuf.txt
│   ├── domains
│   ├── wayback.txt
│   ├── katana.txt
│   ├── waymore.txt
│   ├── crawley.txt
│   ├── waybackrobots.txt
│   ├── urls.txt
│   └── aquatone/
└── domain2.com/
    └── ...
Options
Project Name: The name of the project directory where results will be saved.

Domains: One or more domains to perform reconnaissance on.

Example
Command
bash
Copy
./autorecon.sh MyProject example.com
Output
Copy
[+] Project directory created: MyProject

[+] Processing domain: example.com
[+] Directory created: MyProject/example.com
[+] Running passive subdomain enumeration...
[+] Passive subdomain enumeration completed. Results saved to domains.txt
[+] Filtering live domains...
[+] Live domains filtered. Results saved to domain.live
[+] Running active subdomain enumeration...
[+] Active subdomain enumeration completed. Results saved to domains
[+] Running URL discovery and crawling...
[+] URL discovery and crawling completed. Results saved to urls.txt
[+] Running Aquatone for inspection...
[+] Aquatone inspection completed. Results saved to aquatone/ directory
[+] Done processing domain: example.com. Results are saved in the 'MyProject/example.com' directory.

[+] All domains processed. Results are saved in the 'MyProject' directory.
Tools Used
Subdomain Enumeration:

amass

subfinder

sublist3r

Live Domain Filtering:

httpx

Active Subdomain Enumeration:

ffuf

URL Discovery:

waybackurls

katana

waymore

crawley

Visual Inspection:

aquatone

Contributing
Contributions are welcome! If you'd like to contribute to AutoRecon, please follow these steps:

Fork the repository.

Create a new branch for your feature or bugfix.

Commit your changes.

Submit a pull request.

License
AutoRecon is licensed under the MIT License. See the LICENSE file for details.

Acknowledgments
Thanks to the developers of the tools integrated into AutoRecon.

Inspired by various open-source reconnaissance tools and workflows.

Contact
For questions, feedback, or support, feel free to reach out:

Twitter: @omarsamy10

Email: omar@example.com

Enjoy using AutoRecon! 🚀