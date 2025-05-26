# Use an official Debian/Ubuntu base image as it's similar to what the install script expects
FROM ubuntu:22.04

# Set environment variables for non-interactive apt and Go installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOROOT=/usr/local/go
ENV GOPATH=/go

# Install prerequisites
RUN apt update && \
    apt install -y --no-install-recommends \
    git \
    curl \
    wget \
    python3 \
    python3-pip \
    golang \
    libcurl4-openssl-dev \
    libssl-dev \
    unzip \
    dnsutils \
    iputils-ping \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install pipx and ensure its path
RUN python3 -m pip install --no-cache-dir --user pipx && \
    python3 -m pipx ensurepath

# Set PATH for pipx and Go binaries for subsequent RUN commands
ENV PATH="/root/.local/bin:/go/bin:${PATH}"

# Create a directory for tools outside Go's default path (e.g., for Python tools cloned)
RUN mkdir -p /opt/tools

# Install Go-based tools
# Note: These tools are installed to /go/bin inside the container
RUN go install github.com/owasp-amass/amass/v3/...@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/mhmdiaa/waybackrobots@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    go install github.com/OJ/gobuster/v3/...@latest

# Install Python-based tools by cloning and installing dependencies
# Sublist3r
RUN git clone https://github.com/aboul3la/Sublist3r.git /opt/tools/Sublist3r && \
    pip3 install --no-cache-dir -r /opt/tools/Sublist3r/requirements.txt --break-system-packages

# dnsrecon
RUN git clone https://github.com/darkoperator/dnsrecon.git /opt/tools/dnsrecon && \
    pip3 install --no-cache-dir -r /opt/tools/dnsrecon/requirements.txt --break-system-packages && \
    cd /opt/tools/dnsrecon && python3 setup.py install && cd /

# ParamSpider
RUN git clone https://github.com/devanshbatham/ParamSpider.git /opt/tools/ParamSpider && \
    pip3 install --no-cache-dir -r /opt/tools/ParamSpider/requirements.txt --break-system-packages

# SecretFinder
RUN git clone https://github.com/m4ll0k/SecretFinder.git /opt/tools/SecretFinder && \
    pip3 install --no-cache-dir -r /opt/tools/SecretFinder/requirements.txt --break-system-packages

# Install seclists
RUN apt install -y seclists

# Update Nuclei templates
RUN nuclei -update-templates || echo "Failed to update Nuclei templates. Internet connectivity issue?"

# Copy the autorecon script and config file into the container
WORKDIR /app
COPY autorecon.py .
COPY config.ini .

# Make autorecon executable and set up symlinks for cloned Python tools
RUN chmod +x autorecon.py && \
    ln -s /app/autorecon.py /usr/local/bin/autorecon && \
    ln -s /opt/tools/Sublist3r/sublist3r.py /usr/local/bin/sublist3r && \
    ln -s /opt/tools/ParamSpider/paramspider.py /usr/local/bin/paramspider && \
    ln -s /opt/tools/SecretFinder/SecretFinder.py /usr/local/bin/secretfinder

# Create a default config.ini at /usr/local/bin/ if it doesn't exist already
# (autorecon.py expects it in the same directory or where it's executed)
# We copied it to /app, let's also put it in /usr/local/bin for consistency
RUN cp /app/config.ini /usr/local/bin/config.ini

# Set entrypoint to autorecon for easy execution
ENTRYPOINT ["autorecon"]

# Default command if no arguments are provided
CMD ["--help"]