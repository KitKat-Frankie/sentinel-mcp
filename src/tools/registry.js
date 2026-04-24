// src/tools/registry.js
// Centralized tool definitions for all security tools
// Each tool: { name, description, category, schema, execute(args) }

import { z } from "zod";
import { execTool } from "./executor.js";

// Helper: build a simple exec-based tool
function shellTool(name, description, category, schema, buildCmd) {
  return {
    name, description, category, schema,
    execute: async (args) => {
      const { cmd, cmdArgs, env } = buildCmd(args);
      return execTool(cmd, cmdArgs, { env, timeout: args.timeout || 300 });
    },
  };
}

// RECON & OSINT

const subfinder = shellTool(
  "subfinder",
  "Passive subdomain enumeration via 40+ sources (Shodan, VirusTotal, crt.sh, etc.)",
  "Recon & OSINT",
  {
    domain: z.string().describe("Target domain to enumerate subdomains for"),
    sources: z.string().optional().describe("Comma-separated list of sources to use"),
    recursive: z.boolean().optional().describe("Enable recursive subdomain enumeration"),
    timeout: z.number().optional().describe("Timeout in seconds (default 300)"),
  },
  (args) => {
    const cmdArgs = ["-d", args.domain, "-silent"];
    if (args.sources) cmdArgs.push("-sources", args.sources);
    if (args.recursive) cmdArgs.push("-recursive");
    return { cmd: "subfinder", cmdArgs };
  }
);

const assetfinder = shellTool(
  "assetfinder",
  "Fast passive subdomain discovery using certificate transparency and web archives",
  "Recon & OSINT",
  {
    domain: z.string().describe("Target domain"),
    subs_only: z.boolean().optional().describe("Only include subdomains of the given domain"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = [];
    if (args.subs_only) cmdArgs.push("--subs-only");
    cmdArgs.push(args.domain);
    return { cmd: "assetfinder", cmdArgs };
  }
);

const amass = shellTool(
  "amass",
  "Deep OSINT-driven subdomain enumeration with DNS and scraping",
  "Recon & OSINT",
  {
    domain: z.string().describe("Target domain"),
    passive: z.boolean().optional().default(true).describe("Passive mode only (no active probing)"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = ["enum"];
    if (args.passive) cmdArgs.push("-passive");
    cmdArgs.push("-d", args.domain);
    return { cmd: "amass", cmdArgs };
  }
);

const crtsh = {
  name: "crtsh",
  description: "Certificate transparency log lookup to discover subdomains via crt.sh",
  category: "Recon & OSINT",
  schema: {
    domain: z.string().describe("Target domain to search in certificate logs"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  execute: async (args) => {
    return execTool("curl", [
      "-s", `https://crt.sh/?q=%25.${args.domain}&output=json`,
    ], { timeout: args.timeout || 60 });
  },
};

const waybackurls = shellTool(
  "waybackurls",
  "Extract archived URLs from Wayback Machine to surface old/forgotten endpoints",
  "Recon & OSINT",
  {
    domain: z.string().describe("Target domain"),
    no_subs: z.boolean().optional().describe("Exclude subdomains"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = [];
    if (args.no_subs) cmdArgs.push("-no-subs");
    return {
      cmd: "sh",
      cmdArgs: ["-c", `echo "${args.domain}" | waybackurls ${cmdArgs.join(" ")}`],
    };
  }
);

// DNS

const dnsx = shellTool(
  "dnsx",
  "Bulk DNS resolution for A, MX, NS, TXT, CNAME, PTR records; DNS takeover detection",
  "DNS",
  {
    domain: z.string().describe("Domain or file with domains (one per line)"),
    record_type: z.enum(["a", "aaaa", "mx", "ns", "txt", "cname", "ptr", "soa"]).optional().describe("DNS record type"),
    wordlist: z.string().optional().describe("Wordlist for subdomain bruteforce"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = ["-silent"];
    if (args.record_type) cmdArgs.push(`-${args.record_type}`);
    if (args.wordlist) cmdArgs.push("-w", args.wordlist);
    return {
      cmd: "sh",
      cmdArgs: ["-c", `echo "${args.domain}" | dnsx ${cmdArgs.join(" ")}`],
    };
  }
);

const alterx = shellTool(
  "alterx",
  "Subdomain permutation and wordlist generation based on patterns and input domains",
  "DNS",
  {
    domain: z.string().describe("Target domain for permutation"),
    pattern: z.string().optional().describe("Custom pattern for permutations"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = ["-silent"];
    if (args.pattern) cmdArgs.push("-p", args.pattern);
    return {
      cmd: "sh",
      cmdArgs: ["-c", `echo "${args.domain}" | alterx ${cmdArgs.join(" ")}`],
    };
  }
);

const shuffledns = shellTool(
  "shuffledns",
  "Wildcard-aware subdomain bruteforce using massdns for high-speed DNS resolution",
  "DNS",
  {
    domain: z.string().describe("Target domain"),
    wordlist: z.string().optional().default("/usr/share/wordlists/dns/subdomains-top1million-5000.txt").describe("Wordlist path"),
    resolvers: z.string().optional().default("/usr/share/wordlists/dns/resolvers.txt").describe("Resolvers file path"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => ({
    cmd: "shuffledns",
    cmdArgs: ["-d", args.domain, "-w", args.wordlist, "-r", args.resolvers, "-silent"],
  })
);

// PORT SCANNING

const nmap = shellTool(
  "nmap",
  "Port scanning with service detection, OS fingerprinting, and NSE script support",
  "Port Scanning",
  {
    target: z.string().describe("Target IP, hostname, or CIDR range"),
    ports: z.string().optional().describe("Port specification (e.g. '80,443' or '1-1000')"),
    scan_type: z.enum(["syn", "connect", "udp", "version", "os"]).optional().describe("Scan type"),
    scripts: z.string().optional().describe("NSE scripts to run (e.g. 'vuln,default')"),
    flags: z.string().optional().describe("Additional raw nmap flags"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = [];
    if (args.scan_type === "syn") cmdArgs.push("-sS");
    else if (args.scan_type === "connect") cmdArgs.push("-sT");
    else if (args.scan_type === "udp") cmdArgs.push("-sU");
    else if (args.scan_type === "version") cmdArgs.push("-sV");
    else if (args.scan_type === "os") cmdArgs.push("-O");
    if (args.ports) cmdArgs.push("-p", args.ports);
    if (args.scripts) cmdArgs.push("--script", args.scripts);
    if (args.flags) cmdArgs.push(...args.flags.split(" "));
    cmdArgs.push(args.target);
    return { cmd: "nmap", cmdArgs };
  }
);

const masscan = shellTool(
  "masscan",
  "Internet-scale TCP port scanning at up to 10 million packets per second",
  "Port Scanning",
  {
    target: z.string().describe("Target IP or CIDR range"),
    ports: z.string().optional().default("1-65535").describe("Port range"),
    rate: z.number().optional().default(1000).describe("Packets per second"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => ({
    cmd: "masscan",
    cmdArgs: [args.target, "-p", args.ports, "--rate", String(args.rate), "--open"],
  })
);

const rustscan = shellTool(
  "rustscan",
  "Ultra-fast port scanner that discovers open ports and pipes to nmap for service detection",
  "Port Scanning",
  {
    target: z.string().describe("Target IP or hostname"),
    ports: z.string().optional().describe("Port range (default: all ports)"),
    batch_size: z.number().optional().default(4500).describe("Batch size for scanning"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = ["-a", args.target, "-b", String(args.batch_size), "--greppable"];
    if (args.ports) cmdArgs.push("-p", args.ports);
    return { cmd: "rustscan", cmdArgs };
  }
);

// WEB DISCOVERY

const httpx = shellTool(
  "httpx",
  "HTTP probing with status codes, titles, tech fingerprinting, and response analysis",
  "Web Discovery",
  {
    target: z.string().describe("URL or domain to probe"),
    status_code: z.boolean().optional().default(true).describe("Show status code"),
    title: z.boolean().optional().default(true).describe("Show page title"),
    tech_detect: z.boolean().optional().describe("Enable technology detection"),
    follow_redirects: z.boolean().optional().describe("Follow HTTP redirects"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = ["-silent"];
    if (args.status_code) cmdArgs.push("-sc");
    if (args.title) cmdArgs.push("-title");
    if (args.tech_detect) cmdArgs.push("-td");
    if (args.follow_redirects) cmdArgs.push("-fr");
    return {
      cmd: "sh",
      cmdArgs: ["-c", `echo "${args.target}" | httpx ${cmdArgs.join(" ")}`],
    };
  }
);

const katana = shellTool(
  "katana",
  "Fast web crawler for endpoint and JavaScript file discovery",
  "Web Discovery",
  {
    target: z.string().describe("Target URL to crawl"),
    depth: z.number().optional().default(2).describe("Crawl depth"),
    js_crawl: z.boolean().optional().describe("Enable JavaScript crawling"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = ["-u", args.target, "-d", String(args.depth), "-silent"];
    if (args.js_crawl) cmdArgs.push("-jc");
    return { cmd: "katana", cmdArgs };
  }
);

const ffuf = shellTool(
  "ffuf",
  "Directory, file, and virtual host fuzzing with flexible wordlist support",
  "Web Discovery",
  {
    url: z.string().describe("Target URL with FUZZ keyword (e.g. https://target.com/FUZZ)"),
    wordlist: z.string().optional().default("/usr/share/wordlists/web/common.txt").describe("Wordlist path"),
    method: z.enum(["GET", "POST", "PUT", "DELETE"]).optional().default("GET").describe("HTTP method"),
    filter_code: z.string().optional().describe("Filter by status codes (e.g. '404,403')"),
    extensions: z.string().optional().describe("File extensions to append (e.g. '.php,.html')"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = ["-u", args.url, "-w", args.wordlist, "-X", args.method];
    if (args.filter_code) cmdArgs.push("-fc", args.filter_code);
    if (args.extensions) cmdArgs.push("-e", args.extensions);
    return { cmd: "ffuf", cmdArgs };
  }
);

const gobuster = shellTool(
  "gobuster",
  "Directory/file brute-forcing and DNS subdomain enumeration",
  "Web Discovery",
  {
    mode: z.enum(["dir", "dns", "vhost"]).default("dir").describe("Gobuster mode"),
    target: z.string().describe("Target URL (dir/vhost) or domain (dns)"),
    wordlist: z.string().optional().default("/usr/share/wordlists/web/common.txt").describe("Wordlist path"),
    extensions: z.string().optional().describe("File extensions (dir mode, e.g. 'php,html')"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = [args.mode];
    if (args.mode === "dir" || args.mode === "vhost") cmdArgs.push("-u", args.target);
    else cmdArgs.push("-d", args.target);
    cmdArgs.push("-w", args.wordlist, "-q");
    if (args.extensions && args.mode === "dir") cmdArgs.push("-x", args.extensions);
    return { cmd: "gobuster", cmdArgs };
  }
);

const arjun = shellTool(
  "arjun",
  "Hidden HTTP parameter discovery for GET, POST, JSON, and XML endpoints",
  "Web Discovery",
  {
    url: z.string().describe("Target URL"),
    method: z.enum(["GET", "POST", "JSON", "XML"]).optional().default("GET").describe("HTTP method"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => ({
    cmd: "arjun",
    cmdArgs: ["-u", args.url, "-m", args.method],
  })
);

// VULNERABILITY SCANNING

const nuclei = shellTool(
  "nuclei",
  "Template-based vulnerability scanner for CVEs, misconfigurations, exposed panels, and default credentials",
  "Vuln Scanning",
  {
    target: z.string().describe("Target URL or file with URLs"),
    templates: z.string().optional().describe("Specific template or directory"),
    severity: z.string().optional().describe("Filter by severity (e.g. 'critical,high')"),
    tags: z.string().optional().describe("Filter by tags (e.g. 'cve,rce')"),
    rate_limit: z.number().optional().default(150).describe("Max requests per second"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = ["-u", args.target, "-silent", "-rl", String(args.rate_limit)];
    if (args.templates) cmdArgs.push("-t", args.templates);
    if (args.severity) cmdArgs.push("-severity", args.severity);
    if (args.tags) cmdArgs.push("-tags", args.tags);
    return { cmd: "nuclei", cmdArgs };
  }
);

const nuclei_update = {
  name: "nuclei_update_templates",
  description: "Update nuclei templates to the latest community release",
  category: "Vuln Scanning",
  schema: {},
  execute: async () => execTool("nuclei", ["-update-templates", "-silent"], { timeout: 120 }),
};

const wpscan = shellTool(
  "wpscan",
  "WordPress vulnerability scanner for plugins, themes, users, and known CVEs",
  "Vuln Scanning",
  {
    url: z.string().describe("WordPress site URL"),
    enumerate: z.string().optional().default("vp,vt,u").describe("Enumerate: vp (plugins), vt (themes), u (users)"),
    api_token: z.string().optional().describe("WPScan API token for vulnerability data"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = ["--url", args.url, "-e", args.enumerate, "--no-banner"];
    if (args.api_token) cmdArgs.push("--api-token", args.api_token);
    return { cmd: "wpscan", cmdArgs };
  }
);

const sslscan = shellTool(
  "sslscan",
  "SSL/TLS analysis - weak ciphers, expired certificates, BEAST, POODLE, Heartbleed",
  "Vuln Scanning",
  {
    target: z.string().describe("Target host:port (e.g. example.com:443)"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => ({
    cmd: "sslscan",
    cmdArgs: ["--no-colour", args.target],
  })
);

const http_headers = {
  name: "http_headers_analyze",
  description: "HTTP security headers audit - CSP, HSTS, X-Frame-Options, and more",
  category: "Vuln Scanning",
  schema: {
    url: z.string().describe("Target URL to analyze headers"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  execute: async (args) => {
    return execTool("curl", [
      "-sI", "-L", "--max-time", String(args.timeout || 30), args.url,
    ], { timeout: args.timeout || 30 });
  },
};

// EXPLOITATION

const sqlmap = shellTool(
  "sqlmap",
  "Automated SQL injection detection and exploitation with database enumeration",
  "Exploitation",
  {
    url: z.string().describe("Target URL with parameter (e.g. http://target.com/page?id=1)"),
    data: z.string().optional().describe("POST data string"),
    level: z.number().optional().default(1).describe("Level of tests (1-5)"),
    risk: z.number().optional().default(1).describe("Risk of tests (1-3)"),
    batch: z.boolean().optional().default(true).describe("Non-interactive mode"),
    dbs: z.boolean().optional().describe("Enumerate databases"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = ["-u", args.url, "--level", String(args.level), "--risk", String(args.risk)];
    if (args.data) cmdArgs.push("--data", args.data);
    if (args.batch) cmdArgs.push("--batch");
    if (args.dbs) cmdArgs.push("--dbs");
    return { cmd: "sqlmap", cmdArgs };
  }
);

const commix = shellTool(
  "commix",
  "OS command injection testing for web applications",
  "Exploitation",
  {
    url: z.string().describe("Target URL"),
    data: z.string().optional().describe("POST data"),
    level: z.number().optional().default(1).describe("Level (1-3)"),
    batch: z.boolean().optional().default(true).describe("Non-interactive mode"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = ["--url", args.url, "--level", String(args.level)];
    if (args.data) cmdArgs.push("--data", args.data);
    if (args.batch) cmdArgs.push("--batch");
    return { cmd: "commix", cmdArgs };
  }
);

const smuggler = shellTool(
  "smuggler",
  "HTTP request smuggling detection for CL.TE, TE.CL, and TE.TE variants",
  "Exploitation",
  {
    url: z.string().describe("Target URL"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => ({
    cmd: "python3",
    cmdArgs: ["/opt/smuggler/smuggler.py", "-u", args.url],
  })
);

// TLS / CLOUD

const cero = shellTool(
  "cero",
  "Extract subdomains from TLS certificate Subject Alternative Names",
  "TLS Recon",
  {
    target: z.string().describe("Target host or CIDR"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => ({
    cmd: "cero",
    cmdArgs: [args.target],
  })
);

const scoutsuite = shellTool(
  "scoutsuite",
  "Multi-cloud security posture audit for AWS, GCP, and Azure",
  "Cloud Security",
  {
    provider: z.enum(["aws", "gcp", "azure"]).describe("Cloud provider"),
    profile: z.string().optional().describe("AWS profile or credentials"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = [args.provider];
    if (args.profile) cmdArgs.push("--profile", args.profile);
    return { cmd: "scout", cmdArgs };
  }
);

// PASSWORD CRACKING

const hydra = shellTool(
  "hydra",
  "Fast parallel network login brute forcer supporting 50+ protocols",
  "Password Cracking",
  {
    target: z.string().describe("Target host"),
    service: z.string().describe("Service to attack (e.g. ssh, ftp, http-post-form)"),
    username: z.string().optional().describe("Single username or username file path"),
    password_list: z.string().optional().default("/usr/share/wordlists/passwords/rockyou-50k.txt").describe("Password wordlist"),
    options: z.string().optional().describe("Additional options (e.g. form parameters)"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = [];
    if (args.username) {
      if (args.username.startsWith("/")) cmdArgs.push("-L", args.username);
      else cmdArgs.push("-l", args.username);
    }
    cmdArgs.push("-P", args.password_list);
    if (args.options) cmdArgs.push(...args.options.split(" "));
    cmdArgs.push(args.target, args.service);
    return { cmd: "hydra", cmdArgs };
  }
);

const hashcat = shellTool(
  "hashcat",
  "World's fastest password cracker supporting 300+ hash types",
  "Password Cracking",
  {
    hash_file: z.string().describe("Path to file containing hashes"),
    hash_type: z.number().default(0).describe("Hash type number (e.g. 0=MD5, 1000=NTLM)"),
    wordlist: z.string().optional().default("/usr/share/wordlists/passwords/rockyou-50k.txt").describe("Wordlist path"),
    rules: z.string().optional().describe("Rule file path"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = ["-m", String(args.hash_type), args.hash_file, args.wordlist, "--force"];
    if (args.rules) cmdArgs.push("-r", args.rules);
    return { cmd: "hashcat", cmdArgs };
  }
);

const john = shellTool(
  "john",
  "John the Ripper - versatile hash cracker with auto-detection",
  "Password Cracking",
  {
    hash_file: z.string().describe("Path to file containing hashes"),
    wordlist: z.string().optional().default("/usr/share/wordlists/passwords/rockyou-50k.txt").describe("Wordlist path"),
    format: z.string().optional().describe("Force hash format (e.g. raw-md5, ntlm)"),
    timeout: z.number().optional().describe("Timeout in seconds"),
  },
  (args) => {
    const cmdArgs = [args.hash_file, "--wordlist=" + args.wordlist];
    if (args.format) cmdArgs.push("--format=" + args.format);
    return { cmd: "john", cmdArgs };
  }
);

// UTILITIES

const run_command = {
  name: "run_command",
  description: "Execute any shell command inside the Sentinel container",
  category: "Utilities",
  schema: {
    command: z.string().describe("Shell command to execute"),
    timeout: z.number().optional().default(120).describe("Timeout in seconds"),
  },
  execute: async (args) => {
    return execTool("sh", ["-c", args.command], { timeout: args.timeout });
  },
};

const wordlist_list = {
  name: "wordlist_list",
  description: "List all available wordlists installed in the container",
  category: "Utilities",
  schema: {},
  execute: async () => {
    return execTool("sh", ["-c", "find /usr/share/wordlists -type f | sort"], { timeout: 30 });
  },
};

const wordlist_search = {
  name: "wordlist_search",
  description: "Search for wordlists by keyword or attack type",
  category: "Utilities",
  schema: {
    keyword: z.string().describe("Keyword to search for (e.g. 'dns', 'passwords', 'web')"),
  },
  execute: async (args) => {
    return execTool("sh", ["-c", `find /usr/share/wordlists -type f | grep -i "${args.keyword}"`], { timeout: 30 });
  },
};

// EXPORT ALL TOOLS

export const ALL_TOOLS = [
  subfinder, assetfinder, amass, crtsh, waybackurls,
  dnsx, alterx, shuffledns,
  nmap, masscan, rustscan,
  httpx, katana, ffuf, gobuster, arjun,
  nuclei, nuclei_update, wpscan, sslscan, http_headers,
  sqlmap, commix, smuggler,
  cero, scoutsuite,
  hydra, hashcat, john,
  run_command, wordlist_list, wordlist_search,
];
