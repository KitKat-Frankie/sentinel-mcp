# Sentinel MCP

**Self-hosted security testing MCP server - no credits, no tokens, no limits.**

A Bolt-compatible alternative that bundles 30+ penetration testing tools in a single Docker container, exposed as MCP tools you can call directly from Claude Desktop, Claude Code, or any MCP client.

## Quick Start

### 1. Build and Run

```bash
docker compose up -d --build

# Or manually:
docker build -t sentinel .
docker run -d --name sentinel -p 3001:3001 \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v sentinel-data:/data \
  sentinel
```

### 2. Connect to Claude Desktop

Add to your Claude Desktop MCP config:

```json
{
  "mcpServers": {
    "sentinel": {
      "url": "http://localhost:3001/sse"
    }
  }
}
```

With auth token:

```json
{
  "mcpServers": {
    "sentinel": {
      "url": "http://localhost:3001/sse",
      "headers": {
        "Authorization": "Bearer your-secret-token-here"
      }
    }
  }
}
```

### 3. Connect to Claude Code (stdio)

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "docker",
      "args": ["exec", "-i", "sentinel", "node", "src/stdio.js"]
    }
  }
}
```

### 4. Verify

```bash
curl http://localhost:3001/health
curl http://localhost:3001/tools
```

## Tools (30+)

### Recon and OSINT
| Tool | Description |
|---|---|
| `subfinder` | Passive subdomain enumeration via 40+ sources |
| `assetfinder` | Fast subdomain discovery via cert transparency |
| `amass` | Deep OSINT subdomain enumeration |
| `crtsh` | Certificate transparency log lookup |
| `waybackurls` | Archived URLs from Wayback Machine |

### DNS
| Tool | Description |
|---|---|
| `dnsx` | Bulk DNS resolution (A, MX, NS, TXT, CNAME, PTR) |
| `alterx` | Subdomain permutation and wordlist generation |
| `shuffledns` | Wildcard-aware subdomain bruteforce |

### Port Scanning
| Tool | Description |
|---|---|
| `nmap` | Port scanning, service detection, OS fingerprinting |
| `masscan` | Internet-scale TCP scanning |
| `rustscan` | Ultra-fast port scanner with nmap integration |

### Web Discovery
| Tool | Description |
|---|---|
| `httpx` | HTTP probing, tech fingerprinting |
| `katana` | Web crawling, JS file discovery |
| `ffuf` | Directory/file/vhost fuzzing |
| `gobuster` | Directory brute-forcing and DNS enumeration |
| `arjun` | Hidden HTTP parameter discovery |

### Vulnerability Scanning
| Tool | Description |
|---|---|
| `nuclei` | Template-based vuln scanning (CVEs, misconfigs) |
| `nuclei_update_templates` | Update nuclei templates |
| `wpscan` | WordPress vulnerability scanner |
| `sslscan` | SSL/TLS weakness analysis |
| `http_headers_analyze` | HTTP security headers audit |

### Exploitation
| Tool | Description |
|---|---|
| `sqlmap` | SQL injection detection and exploitation |
| `commix` | OS command injection testing |
| `smuggler` | HTTP request smuggling detection |

### TLS / Cloud
| Tool | Description |
|---|---|
| `cero` | TLS cert Subject Alternative Name extraction |
| `scoutsuite` | Cloud security posture audit (AWS/GCP/Azure) |

### Password Cracking
| Tool | Description |
|---|---|
| `hydra` | Parallel network login brute forcer |
| `hashcat` | GPU-accelerated hash cracking |
| `john` | John the Ripper hash cracker |

### Utilities
| Tool | Description |
|---|---|
| `run_command` | Execute any shell command in the container |
| `wordlist_list` | List all installed wordlists |
| `wordlist_search` | Search wordlists by keyword |

## Common Workflows

### Full Recon
1. subfinder / amass - discover subdomains
2. dnsx - resolve live hosts
3. httpx - probe HTTP services
4. katana - crawl live hosts
5. waybackurls - find old endpoints

### Web Vuln Discovery
1. httpx - confirm alive, fingerprint
2. ffuf / gobuster - fuzz directories
3. arjun - discover hidden params
4. nuclei - template-based vuln scan
5. sqlmap / commix - targeted exploitation

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3001` | Server port |
| `HOST` | `0.0.0.0` | Listen address |
| `MCP_AUTH_TOKEN` | _(empty)_ | Bearer token for auth (optional) |

Docker capabilities `NET_RAW` and `NET_ADMIN` are required for nmap and masscan.

## Bolt vs Sentinel

| Feature | Bolt | Sentinel |
|---|---|---|
| Credit/Token System | Yes (limited) | **None - unlimited** |
| Self-hosted | Docker | Docker |
| Tool Count | 24 | **30+** |
| Transport | HTTP/SSE | HTTP/SSE + Stdio |
| License | AGPL-3.0 | MIT |
| Dependencies | Bun runtime | Node.js |

## Security

Only scan targets you have explicit authorization to test. Unauthorized scanning is illegal in most jurisdictions.

## License

MIT
