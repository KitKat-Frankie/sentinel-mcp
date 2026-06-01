# Sentinel MCP - Self-hosted security tool server
# Ubuntu 24.04 + Node.js + Go tools + Python tools
# No credits, no tokens, no limits

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV NODE_ENV=production

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git unzip wget jq \
    nmap masscan openssl socat dnsutils netcat-openbsd whois \
    sslscan nikto \
    golang-go build-essential \
    python3 python3-pip python3-venv \
    ruby ruby-dev \
    hashcat john \
    hydra medusa \
    libpcap-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Node.js 20
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Go tools (ProjectDiscovery suite + others)
ENV GOPATH=/root/go
ENV PATH="/root/go/bin:$PATH"

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest && \
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/glebarez/cero@latest && \
    go install -v github.com/OJ/gobuster/v3@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/RustScan/RustScan@latest 2>/dev/null || true && \
    rm -rf /root/go/pkg /root/.cache/go-build

# Python tools
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# arjun and scoutsuite are on PyPI
RUN pip install --no-cache-dir arjun scoutsuite

RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
RUN git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix
RUN git clone --depth 1 https://github.com/defparam/smuggler.git /opt/smuggler

# LinkFinder - JavaScript endpoint and secret extraction
RUN git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/linkfinder && \
    pip install --no-cache-dir -r /opt/linkfinder/requirements.txt && \
    chmod +x /opt/linkfinder/linkfinder.py && \
    ln -sf /opt/linkfinder/linkfinder.py /usr/local/bin/linkfinder

# feroxbuster - fast recursive content discovery
RUN curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \
    | bash -s /usr/local/bin 2>/dev/null || \
    ( \
      FEROX_VER=$(curl -s https://api.github.com/repos/epi052/feroxbuster/releases/latest | grep tag_name | cut -d'"' -f4) && \
      curl -sL "https://github.com/epi052/feroxbuster/releases/download/${FEROX_VER}/x86_64-linux-feroxbuster.tar.gz" \
      | tar -xz -C /usr/local/bin feroxbuster \
    ) && \
    chmod +x /usr/local/bin/feroxbuster

# ghauri - advanced SQLi tool (not on PyPI, install via setup.py)
# setup.py registers the 'ghauri' console_scripts entrypoint into the venv
RUN git clone --depth 1 https://github.com/r0oth3x49/ghauri.git /opt/ghauri && \
    pip install --no-cache-dir /opt/ghauri && \
    ln -sf /opt/venv/bin/ghauri /usr/local/bin/ghauri

# nosqlmap - NoSQL injection (MongoDB, CouchDB, Redis, Cassandra)
# Note: nosqlmap is interactive; sentinel wraps it with targeted curl payloads
RUN git clone --depth 1 https://github.com/codingo/NoSQLMap.git /opt/nosqlmap && \
    pip install --no-cache-dir -r /opt/nosqlmap/requirements.txt 2>/dev/null || true && \
    chmod +x /opt/nosqlmap/nosqlmap.py && \
    ln -sf /opt/nosqlmap/nosqlmap.py /usr/local/bin/nosqlmap

# Ruby tools
RUN gem install wpscan --no-doc 2>/dev/null || echo "wpscan install skipped"

# Amass
RUN go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null || true

# Massdns (needed by shuffledns)
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns && \
    cd /tmp/massdns && make && cp bin/massdns /usr/local/bin/ && \
    rm -rf /tmp/massdns

# Kerbrute
RUN go install -v github.com/ropnop/kerbrute@latest 2>/dev/null || true

# Wordlists
RUN mkdir -p /usr/share/wordlists/web \
             /usr/share/wordlists/dns \
             /usr/share/wordlists/passwords \
             /usr/share/wordlists/fuzzing

RUN curl -sL -o /usr/share/wordlists/web/common.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt && \
    curl -sL -o /usr/share/wordlists/web/directory-list-2.3-medium.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt && \
    curl -sL -o /usr/share/wordlists/web/raft-medium-files.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt && \
    curl -sL -o /usr/share/wordlists/web/api-endpoints.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt

RUN curl -sL -o /usr/share/wordlists/dns/subdomains-top1million-5000.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt && \
    curl -sL -o /usr/share/wordlists/dns/subdomains-top1million-20000.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt

RUN curl -sL -o /usr/share/wordlists/dns/resolvers.txt \
    https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt 2>/dev/null || \
    printf '8.8.8.8\n8.8.4.4\n1.1.1.1\n9.9.9.9\n' > /usr/share/wordlists/dns/resolvers.txt

RUN curl -sL -o /usr/share/wordlists/passwords/rockyou-50k.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt 2>/dev/null || \
    echo "password123" > /usr/share/wordlists/passwords/rockyou-50k.txt

RUN nuclei -update-templates -silent 2>/dev/null || true

RUN ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    ln -sf /opt/commix/commix.py /usr/local/bin/commix-bin && \
    ln -sf /opt/venv/bin/arjun /usr/local/bin/arjun && \
    ln -sf /opt/venv/bin/scout /usr/local/bin/scout

# Application
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY src/ ./src/

RUN mkdir -p /data
VOLUME ["/data"]

ENV PORT=3001
ENV HOST=0.0.0.0

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:${PORT:-3001}/health || exit 1

CMD ["node", "src/server.js"]
