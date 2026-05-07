# Sentinel MCP

**Self-hosted security testing MCP server - no credits, no tokens, no limits.**

A Bolt-compatible alternative that bundles 30+ penetration testing tools in a single Docker container, exposed as MCP tools you can call directly from Claude Desktop, Claude Code, or any MCP client.

## Prerequisites

- **Docker Desktop** installed and running ([download](https://www.docker.com/products/docker-desktop/))
- **Git** installed ([download](https://git-scm.com/downloads))
- At least **4GB RAM** available for Docker (the first build compiles Go tools)
- Port **3001** available

## Quick Start (Windows - Command Prompt)

### 1. Clone and Build

Open **Command Prompt** and run:

```cmd
git clone https://github.com/KitKat-Frankie/sentinel-mcp.git
cd sentinel-mcp
docker compose up -d --build
```

The first build takes about 10-15 minutes (compiles Go binaries, installs Python/Ruby packages, downloads wordlists). After that, starts are instant.

If you prefer to build and run manually:

```cmd
docker build -t sentinel .
docker run -d --name sentinel -p 3001:3001 ^
  --cap-add NET_RAW --cap-add NET_ADMIN ^
  -v sentinel-data:/data ^
  sentinel
```

> Note: In Command Prompt, use `^` for line continuation (not `\`).

### 2. Verify It Works

```cmd
curl http://localhost:3001/health
curl http://localhost:3001/tools
```

You should see `{"status":"ok","tools":32}` from the health check.

If `curl` is not available, open your browser and navigate to `http://localhost:3001/health`.

### 3. Connect to Claude Desktop

Open your Claude Desktop MCP config file. On Windows it is located at:

```
%APPDATA%\Claude\claude_desktop_config.json
```

You can open it directly from Command Prompt:

```cmd
notepad %APPDATA%\Claude\claude_desktop_config.json
```

Add the following (or merge into your existing config):

```json
{
  "mcpServers": {
    "sentinel": {
      "url": "http://localhost:3001/sse"
    }
  }
}
```

With optional auth token:

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

Then restart Claude Desktop for the changes to take effect.

### 4. Connect to Claude Code (stdio)

If using Claude Code, add to your MCP settings:

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

## Common Docker Commands (Windows CMD)

```cmd
:: Check container status
docker ps

:: View live logs
docker logs -f sentinel

:: Stop the server
docker compose down

:: Restart after changes
docker compose up -d --build

:: Enter the container shell (to test tools manually)
docker exec -it sentinel bash

:: Check disk usage
docker system df
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

To set environment variables, uncomment the `MCP_AUTH_TOKEN` line in `docker-compose.yml`.

Docker capabilities `NET_RAW` and `NET_ADMIN` are required for nmap and masscan.

### Adding Custom Wordlists

Add a volume mount in `docker-compose.yml`:

```yaml
volumes:
  - sentinel-data:/data
  - C:\Users\frank\wordlists:/usr/share/wordlists/custom
```

## Troubleshooting (Windows)

**Docker Desktop not running:** You will see `error during connect: This error may indicate that the docker daemon is not running`. Open Docker Desktop and wait for the engine to start (green icon in system tray).

**Port 3001 already in use:** Change the port in `docker-compose.yml` from `"3001:3001"` to `"3002:3001"` and update your MCP config URL to use port 3002.

**Build fails with network error:** Make sure Docker Desktop has network access. Check Settings > Resources > Network in Docker Desktop.

**Container starts but Claude does not see tools:** Restart Claude Desktop after editing the config file. Check that the config JSON is valid (no trailing commas).

**View container logs for errors:**
```cmd
docker logs sentinel
```

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
