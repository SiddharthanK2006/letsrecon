#!/usr/bin/env python3
import asyncio
import re
import json
import urllib.parse
import urllib.request
import urllib.error
import socket
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

app = FastAPI()
BASE_DIR = Path(__file__).resolve().parent

DB_PATH = BASE_DIR / "recon_history.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Enable foreign keys
    cursor.execute("PRAGMA foreign_keys = ON")
    
    # Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL
        )
    """)
    
    # Scan findings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            data TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
    """)
    conn.commit()
    conn.close()

# Initialize DB on load
init_db()

def start_db_scan(target: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON")
    
    # Delete old scan entry for this target if exists (this cascades deletes to scan_data)
    cursor.execute("DELETE FROM scans WHERE target = ?", (target,))
    
    # Insert new scan
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO scans (target, timestamp) VALUES (?, ?)", (target, now))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def save_parsed_data(scan_id: int, category: str, data: dict):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_data (scan_id, category, data) VALUES (?, ?, ?)",
        (scan_id, category, json.dumps(data))
    )
    conn.commit()
    conn.close()

class DatabaseSavingWebSocket:
    def __init__(self, websocket: WebSocket, scan_id: int):
        self.websocket = websocket
        self.scan_id = scan_id

    async def send_json(self, data: dict):
        if data.get("type") == "parsed_data":
            category = data.get("category")
            parsed_val = data.get("data")
            if self.scan_id and category and parsed_val is not None:
                try:
                    save_parsed_data(self.scan_id, category, parsed_val)
                except Exception as e:
                    # Log silently or stream error if needed
                    pass
        await self.websocket.send_json(data)


# Define modules with their IDs
MODULES = {
    "domain_scraping": {"name": "Domain Scraping", "id": "domain_scraping"},
    "cert_transparency": {"name": "Certificate Transparency", "id": "cert_transparency"},
    "passive_dns": {"name": "Passive DNS & ASN", "id": "passive_dns"},
    "historical_repos": {"name": "Historical Repos", "id": "historical_repos"},
    "code_leakage": {"name": "Code Leakage & Assets", "id": "code_leakage"},
    "human_intel": {"name": "Human Intelligence", "id": "human_intel"},
    "firewall": {"name": "Firewall Detection", "id": "firewall"}
}

def clean_target(target: str) -> str:
    target = target.strip().lower()
    # Strip protocol prefix if present
    if target.startswith("http://"):
        target = target[7:]
    elif target.startswith("https://"):
        target = target[8:]
    # Strip any trailing path or query parameters
    target = target.split("/")[0]
    # Strip port if present
    target = target.split(":")[0]
    return target

def validate_target(target: str) -> bool:
    cleaned = clean_target(target)
    if not cleaned:
        return False
    # Check if target is IP address
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_pattern.match(cleaned):
        # Validate octets
        octets = cleaned.split('.')
        return all(0 <= int(o) <= 255 for o in octets)
    # Domain pattern (alphanumeric, dots, dashes, length check) - strict to prevent injection
    domain_pattern = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,12}$')
    return bool(domain_pattern.match(cleaned))

def http_get(url: str, headers: dict = None, timeout: int = 15) -> str:
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*"
    }
    if headers:
        default_headers.update(headers)
    req = urllib.request.Request(url, headers=default_headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode('utf-8', errors='replace')

async def async_http_get(url: str, headers: dict = None, timeout: int = 15) -> str:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: http_get(url, headers, timeout))

async def stream_command(websocket: WebSocket, command: list, module_id: str, timeout: int = 30):
    """Run command securely and yield lines to frontend, returning stdout block for parsing"""
    output = []
    try:
        # Secure execution: shell=False, command passed as list, sanitised target
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        async def read_stream(stream):
            while True:
                line = await stream.readline()
                if not line:
                    break
                decoded_line = line.decode('utf-8', errors='replace').rstrip()
                output.append(decoded_line)
                await websocket.send_json({
                    "type": "module_data",
                    "module_id": module_id,
                    "data": decoded_line
                })

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    read_stream(process.stdout),
                    read_stream(process.stderr)
                ),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            await websocket.send_json({
                "type": "module_data",
                "module_id": module_id,
                "data": f"[WARNING] Tool '{command[0]}' execution timed out after {timeout} seconds. Terminating process..."
            })
            try:
                process.terminate()
                await process.wait()
            except Exception:
                pass
        else:
            await process.wait()

    except FileNotFoundError:
        # Quietly fail; handled at module level to trigger fallbacks
        raise
    except Exception as e:
        await websocket.send_json({
            "type": "module_data",
            "module_id": module_id,
            "data": f"[ERROR] Subprocess error: {str(e)}"
        })
    return "\n".join(output)


# --- MODULE 1: DOMAIN SCRAPING ---
async def module1_domain_scraping(websocket: WebSocket, target: str):
    module_id = "domain_scraping"
    await websocket.send_json({"type": "module_start", "module_id": module_id})
    subdomains_found = set()

    # Try running local tools first
    commands = [
        (["subfinder", "-d", target, "-silent"], "Subfinder"),
        (["assetfinder", "--subs-only", target], "Assetfinder"),
        (["findomain", "-t", target, "-q"], "Findomain"),
    ]
    
    for cmd, name in commands:
        try:
            await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"--- Running local {name} ---"})
            output = await stream_command(websocket, cmd, module_id)
            # Parse subdomains from output
            for line in output.split("\n"):
                sub = line.strip().lower()
                if sub and target in sub:
                    subdomains_found.add(sub)
                    await websocket.send_json({
                        "type": "parsed_data",
                        "category": "subdomains",
                        "data": {"subdomain": sub, "source": name}
                    })
        except FileNotFoundError:
            await websocket.send_json({
                "type": "module_data", 
                "module_id": module_id, 
                "data": f"[INFO] Local {name} not found. Will use API fallback."
            })

    # Always enrich or fallback with public API scrapers
    await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "--- Fetching Subdomains from Threat Intelligence APIs ---"})
    
    # 1. HackerTarget Host Search
    try:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "Querying HackerTarget..."})
        res = await async_http_get(f"https://api.hackertarget.com/hostsearch/?q={target}", timeout=10)
        for line in res.strip().split("\n"):
            parts = line.split(",")
            if len(parts) >= 1:
                sub = parts[0].strip().lower()
                if sub and target in sub and sub not in subdomains_found:
                    subdomains_found.add(sub)
                    await websocket.send_json({
                        "type": "parsed_data",
                        "category": "subdomains",
                        "data": {"subdomain": sub, "source": "HackerTarget API"}
                    })
                    await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[Found] {sub}"})
    except Exception as e:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[INFO] HackerTarget API bypassed: {str(e)}"})

    # 2. AlienVault OTX Passive DNS
    try:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "Querying AlienVault OTX..."})
        res_text = await async_http_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns", timeout=10)
        res_data = json.loads(res_text)
        for entry in res_data.get("passive_dns", []):
            hostname = entry.get("hostname", "").strip().lower()
            if hostname and target in hostname and hostname not in subdomains_found:
                subdomains_found.add(hostname)
                await websocket.send_json({
                    "type": "parsed_data",
                    "category": "subdomains",
                    "data": {"subdomain": hostname, "source": "AlienVault OTX"}
                })
                await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[Found] {hostname}"})
    except Exception as e:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[INFO] AlienVault OTX bypassed: {str(e)}"})

    # 3. CertSpotter API
    try:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "Querying CertSpotter..."})
        res_text = await async_http_get(f"https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names", timeout=10)
        res_data = json.loads(res_text)
        for entry in res_data:
            for name in entry.get("dns_names", []):
                name = name.strip().lower()
                if name and target in name and name not in subdomains_found:
                    subdomains_found.add(name)
                    await websocket.send_json({
                        "type": "parsed_data",
                        "category": "subdomains",
                        "data": {"subdomain": name, "source": "CertSpotter API"}
                    })
                    await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[Found] {name}"})
    except Exception as e:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[INFO] CertSpotter API bypassed: {str(e)}"})

    await websocket.send_json({"type": "module_complete", "module_id": module_id})


# --- MODULE 2: CERTIFICATE TRANSPARENCY ---
async def module2_certificate_transparency(websocket: WebSocket, target: str):
    module_id = "cert_transparency"
    await websocket.send_json({"type": "module_start", "module_id": module_id})
    seen = set()

    # Query crt.sh with Custom Headers and timeout retries
    url = f"https://crt.sh/?q={urllib.parse.quote(target)}&output=json"
    await websocket.send_json({
        "type": "module_data",
        "module_id": module_id,
        "data": f"Querying Certificate Transparency database: crt.sh"
    })
    
    success = False
    try:
        # crt.sh can be extremely unstable, we try up to 2 times
        for attempt in range(2):
            try:
                res_text = await async_http_get(url, timeout=15)
                data = json.loads(res_text)
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        # Clean wildcards
                        if sub.startswith("*."):
                            sub = sub[2:]
                        if sub and sub not in seen:
                            seen.add(sub)
                            await websocket.send_json({
                                "type": "parsed_data",
                                "category": "certificates",
                                "data": {
                                    "subdomain": sub,
                                    "issuer": entry.get("issuer_name", "Unknown"),
                                    "logged_at": entry.get("entry_timestamp", "Unknown")
                                }
                            })
                            await websocket.send_json({
                                "type": "module_data",
                                "module_id": module_id,
                                "data": f"[Cert] {sub} (Issuer: {entry.get('issuer_name')})"
                            })
                success = True
                break
            except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError, asyncio.TimeoutError) as ex:
                await websocket.send_json({
                    "type": "module_data",
                    "module_id": module_id,
                    "data": f"Attempt {attempt+1} failed: {str(ex)}. Retrying..."
                })
                await asyncio.sleep(2)
    except Exception as e:
        pass

    if not success:
        await websocket.send_json({
            "type": "module_data",
            "module_id": module_id,
            "data": "[WARNING] crt.sh failed. Falling back to CertSpotter for certificate logs."
        })
        # Fallback to CertSpotter API for Certificate Logs
        try:
            res_text = await async_http_get(f"https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=issuer", timeout=12)
            data = json.loads(res_text)
            for entry in data:
                dns_names = entry.get("dns_names", [])
                issuer = entry.get("issuer", {}).get("name", "Unknown")
                logged_at = entry.get("not_before", "Unknown")
                for sub in dns_names:
                    sub = sub.strip().lower()
                    if sub.startswith("*."):
                        sub = sub[2:]
                    if sub and target in sub and sub not in seen:
                        seen.add(sub)
                        await websocket.send_json({
                            "type": "parsed_data",
                            "category": "certificates",
                            "data": {
                                "subdomain": sub,
                                "issuer": issuer,
                                "logged_at": logged_at
                            }
                        })
                        await websocket.send_json({
                            "type": "module_data",
                            "module_id": module_id,
                            "data": f"[Cert] {sub} (Issuer: {issuer})"
                        })
        except Exception as e:
            await websocket.send_json({
                "type": "module_data",
                "module_id": module_id,
                "data": f"[ERROR] Certificate transparency fallback failed: {str(e)}"
            })
            
    await websocket.send_json({"type": "module_complete", "module_id": module_id})


async def query_dnsdumpster(websocket: WebSocket, target: str, module_id: str):
    """Scrapes DNSDumpster for DNS records and hostnames"""
    try:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "Querying dnsdumpster.com web service..."})
        
        loop = asyncio.get_running_loop()
        def fetch_dnsdumpster():
            import urllib.request
            import urllib.parse
            import re
            
            # Step 1: GET dnsdumpster.com to get CSRF token and set session cookie
            req1 = urllib.request.Request(
                "https://dnsdumpster.com/", 
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                }
            )
            csrf_token = ""
            cookie_val = ""
            with urllib.request.urlopen(req1, timeout=10) as resp1:
                html = resp1.read().decode('utf-8', errors='replace')
                headers = resp1.info()
                cookies = headers.get_all('Set-Cookie', [])
                for c in cookies:
                    if 'csrftoken' in c:
                        csrf_token = c.split('csrftoken=')[1].split(';')[0]
                        cookie_val = f"csrftoken={csrf_token}"
                        break
                
                if not csrf_token:
                    # Fallback regex search for CSRF middleware token in HTML
                    m = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', html)
                    if m:
                        csrf_token = m.group(1)
                        cookie_val = f"csrftoken={csrf_token}"
            
            if not csrf_token:
                return None
            
            # Step 2: POST target_domain
            data = urllib.parse.urlencode({
                "csrfmiddlewaretoken": csrf_token,
                "target_domain": target
            }).encode('utf-8')
            
            req2 = urllib.request.Request(
                "https://dnsdumpster.com/",
                data=data,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Referer": "https://dnsdumpster.com/",
                    "Cookie": cookie_val
                }
            )
            with urllib.request.urlopen(req2, timeout=12) as resp2:
                return resp2.read().decode('utf-8', errors='replace')
                
        html = await loop.run_in_executor(None, fetch_dnsdumpster)
        if not html:
            await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "[INFO] Could not retrieve session CSRF token from DNSDumpster."})
            return
            
        # Parse subdomains
        subdomains = set()
        sub_pattern = re.compile(rf'([a-zA-Z0-9][-a-zA-Z0-9.]*\.{re.escape(target)})', re.IGNORECASE)
        for match in sub_pattern.findall(html):
            subdomains.add(match.lower())
            
        for sub in subdomains:
            if sub != target:
                await websocket.send_json({
                    "type": "parsed_data",
                    "category": "subdomains",
                    "data": {"subdomain": sub, "source": "DNSDumpster Scraper"}
                })
                await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[DNSDumpster] Found Host: {sub}"})
                
        # Parse records
        row_pattern = re.compile(r'<tr>\s*<td class="col-md-4">([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,12})<br>.*?</td>\s*<td class="col-md-3">(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})<br>', re.DOTALL | re.IGNORECASE)
        for match in row_pattern.findall(html):
            host = match[0].strip().lower()
            ip = match[1].strip()
            if target in host:
                await websocket.send_json({
                    "type": "parsed_data",
                    "category": "dns_records",
                    "data": {"type": "A", "value": f"{host} -> {ip}", "ttl": "DNSDumpster"}
                })
                await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[DNSDumpster] A Record: {host} -> {ip}"})
                
    except Exception as e:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[INFO] DNSDumpster scraping failed: {str(e)}"})

async def query_dig(websocket: WebSocket, target: str, module_id: str) -> bool:
    """Query DNS using the local dig tool"""
    await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "--- Resolving DNS Records via dig CLI ---"})
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]
    dig_success = False
    
    for rtype in record_types:
        try:
            cmd = ["dig", "+nocmd", "+noall", "+answer", target, rtype]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            output = stdout.decode('utf-8', errors='replace')
            
            lines = output.strip().split("\n")
            has_records = False
            for line in lines:
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                parts = re.split(r'\s+', line, maxsplit=4)
                if len(parts) >= 5:
                    name = parts[0].rstrip('.')
                    ttl = parts[1]
                    val = parts[4].strip('"')
                    
                    await websocket.send_json({
                        "type": "parsed_data",
                        "category": "dns_records",
                        "data": {"type": rtype, "value": val, "ttl": ttl}
                    })
                    await websocket.send_json({
                        "type": "module_data",
                        "module_id": module_id,
                        "data": f"[dig] {rtype} -> {val} (TTL: {ttl})"
                    })
                    has_records = True
                    dig_success = True
                    
            if not has_records:
                await websocket.send_json({
                    "type": "module_data",
                    "module_id": module_id,
                    "data": f"[dig] No records found for type {rtype}"
                })
        except Exception as e:
            await websocket.send_json({
                "type": "module_data",
                "module_id": module_id,
                "data": f"[INFO] dig command execution failed for {rtype}: {str(e)}"
            })
            
    return dig_success

# --- MODULE 3: PASSIVE DNS & ASN ---
async def module3_passive_dns(websocket: WebSocket, target: str):
    module_id = "passive_dns"
    await websocket.send_json({"type": "module_start", "module_id": module_id})

    # Resolving DNS Records: Run local dig first (instant)
    dig_successful = await query_dig(websocket, target, module_id)

    # Python DoH (Always run as enrichment or fallback)
    await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "--- Resolving DNS Records via DNS-over-HTTPS (DoH) ---"})
    
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]
    dns_records = []
    resolved_ips = []
    
    for rtype in record_types:
        doh_success = False
        
        # Try Cloudflare DoH API first
        try:
            url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(target)}&type={rtype}"
            res_text = await async_http_get(url, headers={"Accept": "application/dns-json"}, timeout=8)
            res_data = json.loads(res_text)
            
            answers = res_data.get("Answer", [])
            if answers:
                for ans in answers:
                    val = ans.get("data", "").strip('"')
                    dns_records.append({"type": rtype, "value": val, "ttl": ans.get("TTL", 300)})
                    await websocket.send_json({
                        "type": "parsed_data",
                        "category": "dns_records",
                        "data": {"type": rtype, "value": val, "ttl": ans.get("TTL", 300)}
                    })
                    await websocket.send_json({
                        "type": "module_data",
                        "module_id": module_id,
                        "data": f"[DNS] Cloudflare | {rtype} -> {val}"
                    })
                    if rtype == "A":
                        resolved_ips.append(val)
                doh_success = True
        except Exception:
            pass

        # If Cloudflare fails or yields no results, query Google DoH API
        if not doh_success:
            try:
                url = f"https://dns.google/resolve?name={urllib.parse.quote(target)}&type={rtype}"
                res_text = await async_http_get(url, timeout=8)
                res_data = json.loads(res_text)
                
                answers = res_data.get("Answer", [])
                for ans in answers:
                    val = ans.get("data", "").strip('"')
                    dns_records.append({"type": rtype, "value": val, "ttl": ans.get("TTL", 300)})
                    await websocket.send_json({
                        "type": "parsed_data",
                        "category": "dns_records",
                        "data": {"type": rtype, "value": val, "ttl": ans.get("TTL", 300)}
                    })
                    await websocket.send_json({
                        "type": "module_data",
                        "module_id": module_id,
                        "data": f"[DNS] Google | {rtype} -> {val}"
                    })
                    if rtype == "A":
                        resolved_ips.append(val)
            except Exception as e:
                await websocket.send_json({
                    "type": "module_data",
                    "module_id": module_id,
                    "data": f"[INFO] Google DoH fallback for {rtype} failed: {str(e)}"
                })

    # If no DNS A records returned, resolve host via standard socket resolver
    if not resolved_ips:
        try:
            loop = asyncio.get_running_loop()
            addr_info = await loop.run_in_executor(None, lambda: socket.gethostbyname_ex(target))
            for ip in addr_info[2]:
                resolved_ips.append(ip)
                dns_records.append({"type": "A", "value": ip, "ttl": "Local"})
                await websocket.send_json({
                    "type": "parsed_data",
                    "category": "dns_records",
                    "data": {"type": "A", "value": ip, "ttl": "Local"}
                })
        except Exception as e:
            await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[ERROR] Standard IP resolution failed: {str(e)}"})

    # Get Geolocation and ASN for IPs
    if resolved_ips:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "--- Fetching Geolocation & ASN Details ---"})
        for ip in list(set(resolved_ips))[:3]:  # Limit to first 3 IPs to avoid rate limits
            try:
                res_text = await async_http_get(f"http://ip-api.com/json/{ip}", timeout=8)
                geo = json.loads(res_text)
                if geo.get("status") == "success":
                    geo_data = {
                        "ip": ip,
                        "country": geo.get("country", "Unknown"),
                        "city": geo.get("city", "Unknown"),
                        "org": geo.get("org", "Unknown"),
                        "asn": geo.get("as", "Unknown"),
                        "isp": geo.get("isp", "Unknown"),
                        "lat": geo.get("lat"),
                        "lon": geo.get("lon")
                    }
                    await websocket.send_json({
                        "type": "parsed_data",
                        "category": "geoip",
                        "data": geo_data
                    })
                    await websocket.send_json({
                        "type": "module_data",
                        "module_id": module_id,
                        "data": f"[IP Geo] {ip} | Country: {geo_data['country']} | ISP: {geo_data['isp']} | ASN: {geo_data['asn']}"
                    })
            except Exception as e:
                await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[INFO] GeoIP failed for {ip}: {str(e)}"})

    # DNSDumpster: Run secondary to fetch subdomains/hosts
    try:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "--- Running local dnsdumpster-cli ---"})
        await stream_command(websocket, ["dnsdumpster-cli", target], module_id, timeout=20)
    except FileNotFoundError:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "[INFO] dnsdumpster-cli not found. Running Python DNSDumpster web scraper."})
        await query_dnsdumpster(websocket, target, module_id)

    # Amass Intel: Run with 15s timeout
    try:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "--- Running local Amass Intel ---"})
        await stream_command(websocket, ["amass", "intel", "-d", target, "-whois"], module_id, timeout=15)
    except (FileNotFoundError, Exception) as e:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[INFO] Amass Intel bypassed or failed: {str(e)}"})

    await websocket.send_json({"type": "module_complete", "module_id": module_id})


# --- MODULE 4: HISTORICAL REPOS (WEB ARCHIVES) ---
async def module4_historical_repos(websocket: WebSocket, target: str):
    module_id = "historical_repos"
    await websocket.send_json({"type": "module_start", "module_id": module_id})

    # Try local tools first
    commands = [
        (["waymore", "-i", target, "-mode", "U"], "Waymore"),
        (["gau", target], "GAU"),
    ]
    for cmd, name in commands:
        try:
            await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"--- Running local {name} ---"})
            await stream_command(websocket, cmd, module_id, timeout=15)
        except FileNotFoundError:
            await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[INFO] {name} not found."})

    # 1. AlienVault OTX URL List (Fast & Highly Reliable)
    await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "--- Fetching Historical URLs from AlienVault OTX ---"})
    otx_urls_count = 0
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(target)}/url_list?limit=150"
        res_text = await async_http_get(url, timeout=10)
        res_data = json.loads(res_text)
        
        urls = res_data.get("url_list", [])
        for item in urls:
            orig_url = item.get("url", "")
            if not orig_url:
                continue
            
            # Match mime type or extension
            mimetype = "text/html"
            if "." in orig_url.split("/")[-1]:
                ext = orig_url.split("/")[-1].split(".")[-1].lower()
                if ext in ["js", "css", "png", "jpg", "jpeg", "gif", "svg", "pdf", "json", "xml"]:
                    mimetype = f"application/{ext}" if ext in ["js", "json", "pdf", "xml"] else f"image/{ext}"
            
            status = str(item.get("httpcode") or 200)
            date_raw = item.get("date", "")
            timestamp = date_raw.replace("-", "").replace("T", "").replace(":", "")[:14] if date_raw else ""
            
            await websocket.send_json({
                "type": "parsed_data",
                "category": "wayback_urls",
                "data": {
                    "url": orig_url,
                    "mimetype": mimetype,
                    "status": status,
                    "timestamp": timestamp
                }
            })
            await websocket.send_json({
                "type": "module_data",
                "module_id": module_id,
                "data": f"[OTX URL] [{status}] ({mimetype}) -> {orig_url}"
            })
            otx_urls_count += 1
            
    except Exception as e:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[INFO] AlienVault URL query failed: {str(e)}"})

    # 2. Wayback Machine Scraper Fallback using HTTPS
    await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "--- Fetching Historical Web Archives from Wayback Machine ---"})
    try:
        # Check if target is IP or domain to optimize search query type
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if ip_pattern.match(target):
            url = f"https://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(target)}&output=json&collapse=urlkey&limit=150"
        else:
            url = f"https://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(target)}&matchType=domain&output=json&collapse=urlkey&limit=150"
        res_text = await async_http_get(url, timeout=15)
        data = json.loads(res_text)
        
        if len(data) > 1:
            headers = data[0]
            rows = data[1:]
            for row in rows:
                entry = dict(zip(headers, row))
                orig_url = entry.get("original", "")
                mimetype = entry.get("mimetype", "unknown")
                status = entry.get("statuscode", "200")
                timestamp = entry.get("timestamp", "")
                
                await websocket.send_json({
                    "type": "parsed_data",
                    "category": "wayback_urls",
                    "data": {
                        "url": orig_url,
                        "mimetype": mimetype,
                        "status": status,
                        "timestamp": timestamp
                    }
                })
                await websocket.send_json({
                    "type": "module_data",
                    "module_id": module_id,
                    "data": f"[Wayback URL] [{status}] ({mimetype}) -> {orig_url}"
                })
        elif otx_urls_count == 0:
            await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "No historical URLs found in Wayback Machine."})
    except Exception as e:
        await websocket.send_json({
            "type": "module_data",
            "module_id": module_id,
            "data": f"[INFO] Wayback Machine is offline or unreachable: {str(e)}"
        })
        if otx_urls_count == 0:
            await websocket.send_json({
                "type": "module_data",
                "module_id": module_id,
                "data": "No historical URLs found (Wayback Machine offline & OTX returned 0 results)."
            })

    await websocket.send_json({"type": "module_complete", "module_id": module_id})


# --- MODULE 5: CODE LEAKAGE & EXPOSED ASSETS ---
async def module5_code_leakage(websocket: WebSocket, target: str):
    module_id = "code_leakage"
    await websocket.send_json({"type": "module_start", "module_id": module_id})

    # Try local trufflehog
    try:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "--- Running local Trufflehog ---"})
        await stream_command(websocket, ["trufflehog", "github", "--repo", f"github.com/{target}", "--only-verified"], module_id)
    except FileNotFoundError:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "[INFO] Trufflehog not found. Running Exposed Assets Scanner."})
    except Exception as e:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[INFO] Trufflehog failed: {str(e)}"})

    # Exposed Assets and Configuration File Scanner (Python Native)
    await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "--- Scanning for Exposed Sensitive Files & Tokens ---"})
    
    PATHS_TO_CHECK = [
        (".env", "Environment File", r"(AWS_|SECRET_|PASSWORD|KEY|DATABASE|TOKEN|API|SSH|PRIVATE)"),
        (".git/config", "Git Directory Config", r"\[core\]|url\s*="),
        ("robots.txt", "Robots Configuration", r"Disallow:"),
        (".vscode/sftp.json", "SFTP Config", r"password|host|username"),
        ("wp-config.php", "WordPress Database Config", r"DB_NAME|DB_USER|DB_PASSWORD"),
        ("config.json", "Config File", r"(key|pass|password|token|secret)"),
        (".bash_history", "Shell Command History", r"(ssh |mysql |git clone)"),
        ("package.json", "Node Dependency Manifest", r"\"dependencies\"|scripts"),
    ]

    async def scan_path(path: str, name: str, pattern: str):
        url = f"http://{target}/{path}"
        try:
            loop = asyncio.get_running_loop()
            def fetch_head():
                req = urllib.request.Request(url, method="GET", headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                })
                # Read first 8KB to check for secrets/validity
                with urllib.request.urlopen(req, timeout=5) as response:
                    status = response.status
                    content = response.read(8192).decode("utf-8", errors="replace")
                    return status, content
            
            status, content = await loop.run_in_executor(None, fetch_head)
            if status == 200:
                is_custom_404 = "404" in content.lower() and ("page not found" in content.lower() or "not found" in content.lower())
                if len(content.strip()) > 20 and not is_custom_404:
                    match_found = bool(re.search(pattern, content, re.IGNORECASE))
                    severity = "High" if path in [".env", ".git/config", "wp-config.php", ".vscode/sftp.json"] else "Medium"
                    
                    secrets_found = []
                    aws_match = re.search(r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', content)
                    if aws_match:
                        secrets_found.append(f"AWS Key ID: {aws_match.group(0)}")
                    if "-----BEGIN" in content:
                        secrets_found.append("PEM Private Key block")
                    
                    leak_info = {
                        "path": path,
                        "url": url,
                        "name": name,
                        "status": "Exposed (200 OK)",
                        "severity": severity,
                        "matched_signature": match_found,
                        "details": ", ".join(secrets_found) if secrets_found else "Access configurations exposed"
                    }
                    await websocket.send_json({
                        "type": "parsed_data",
                        "category": "leaks",
                        "data": leak_info
                    })
                    await websocket.send_json({
                        "type": "module_data",
                        "module_id": module_id,
                        "data": f"[ALERT] EXPOSED FILE: {url} (Severity: {severity}) | Matches signature: {match_found}"
                    })
        except Exception:
            pass

    # Scan paths concurrently
    await asyncio.gather(*(scan_path(p, n, sig) for p, n, sig in PATHS_TO_CHECK))
    await websocket.send_json({"type": "module_complete", "module_id": module_id})


# --- MODULE 6: HUMAN INTELLIGENCE & WHOIS ---
async def module6_human_intelligence(websocket: WebSocket, target: str):
    module_id = "human_intel"
    await websocket.send_json({"type": "module_start", "module_id": module_id})

    # WHOIS / RDAP Information Lookup (Python Native)
    await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "--- Fetching Domain Registration Registry (WHOIS / RDAP) ---"})
    try:
        url = f"https://rdap.org/domain/{urllib.parse.quote(target)}"
        res_text = await async_http_get(url, timeout=10)
        data = json.loads(res_text)
        
        events = data.get("events", [])
        created = "Unknown"
        changed = "Unknown"
        expires = "Unknown"
        for event in events:
            action = event.get("eventAction")
            date = event.get("eventDate", "").split("T")[0]
            if action == "registration":
                created = date
            elif action == "last update":
                changed = date
            elif action == "expiration":
                expires = date
                
        registrar = "Unknown"
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    properties = vcard[1]
                    for prop in properties:
                        if prop[0] == "fn":
                            registrar = prop[3]
                            break
                            
        whois_data = {
            "registrar": registrar,
            "created": created,
            "changed": changed,
            "expires": expires
        }
        
        await websocket.send_json({
            "type": "parsed_data",
            "category": "whois",
            "data": whois_data
        })
        await websocket.send_json({
            "type": "module_data",
            "module_id": module_id,
            "data": f"[WHOIS] Registrar: {registrar} | Created: {created} | Expires: {expires}"
        })
    except Exception as e:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[INFO] RDAP WHOIS bypass: {str(e)}"})

    # Wikipedia API Search
    await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "--- Searching Wikipedia Brand & Corp records ---"})
    try:
        root_name = target.split(".")[0]
        search_url = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={urllib.parse.quote(root_name)}&format=json"
        
        headers = {
            "User-Agent": "LetsReconOSINT/1.0 (contact@letsrecon.local; security-research)",
            "Api-User-Agent": "LetsReconOSINT/1.0 (contact@letsrecon.local)"
        }
        res_text = await async_http_get(search_url, headers=headers, timeout=10)
        data = json.loads(res_text)
        search_results = data.get('query', {}).get('search', [])
        
        if not search_results:
            await websocket.send_json({
                "type": "module_data",
                "module_id": module_id,
                "data": "No company/brand records found in Wikipedia"
            })
        else:
            for result in search_results[:3]:
                title = result.get('title')
                snippet = re.sub('<[^<]+?>', '', result.get('snippet', ''))
                pageid = result.get('pageid')
                wiki_info = {
                    "title": title,
                    "snippet": snippet,
                    "url": f"https://en.wikipedia.org/?curid={pageid}"
                }
                await websocket.send_json({
                    "type": "parsed_data",
                    "category": "wiki",
                    "data": wiki_info
                })
                await websocket.send_json({
                    "type": "module_data",
                    "module_id": module_id,
                    "data": f"[Wikipedia] Found Page: {title} | {snippet[:120]}..."
                })
    except Exception as e:
        await websocket.send_json({
            "type": "module_data",
            "module_id": module_id,
            "data": f"[ERROR] Wikipedia lookup failed: {str(e)}"
        })
    
    await websocket.send_json({"type": "module_complete", "module_id": module_id})


# --- MODULE 7: FIREWALL DETECTION (WAF) ---
async def module7_firewall_detection(websocket: WebSocket, target: str):
    module_id = "firewall"
    await websocket.send_json({"type": "module_start", "module_id": module_id})
    await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "--- Running local WAFW00F Firewall Fingerprinting Toolkit ---"})

    waf_detected = False
    waf_name = "None detected"
    waf_manufacturer = "None"
    
    try:
        # Stream the output of wafw00f
        output = await stream_command(websocket, ["wafw00f", target], module_id, timeout=20)
        
        # Analyze output for WAF signatures
        for line in output.splitlines():
            # Check for behind WAF match pattern
            match = re.search(r'is behind\s+([^(]+)(?:\(([^)]+)\))?\s+WAF', line, re.IGNORECASE)
            if match:
                waf_detected = True
                waf_name = match.group(1).strip()
                if match.group(2):
                    waf_manufacturer = match.group(2).strip()
                break
                
        if not waf_detected:
            # Check for generic detection patterns
            for line in output.splitlines():
                if "No WAF detected" in line:
                    break
                if "Generic Detection results" in line or "detected by the generic detection" in line:
                    waf_detected = True
                    waf_name = "Generic WAF Shield"
                    break
                    
    except FileNotFoundError:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": "[INFO] WAFW00F not found on the local system."})
    except Exception as e:
        await websocket.send_json({"type": "module_data", "module_id": module_id, "data": f"[INFO] WAFW00F execution failed: {str(e)}"})

    waf_info = {
        "detected": waf_detected,
        "name": waf_name,
        "manufacturer": waf_manufacturer
    }
    
    await websocket.send_json({
        "type": "parsed_data",
        "category": "waf",
        "data": waf_info
    })
    
    status_msg = f"[WAF] Shield Detected: {waf_name} ({waf_manufacturer})" if waf_detected else "[WAF] Scan finished: No active Firewall shield found."
    await websocket.send_json({
        "type": "module_data",
        "module_id": module_id,
        "data": status_msg
    })
    
    await websocket.send_json({"type": "module_complete", "module_id": module_id})


@app.get("/api/scans")
async def get_scans():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT target, timestamp FROM scans ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        conn.close()
        return [{"target": r[0], "timestamp": r[1]} for r in rows]
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/scan/{target}")
async def get_scan_details(target: str):
    cleaned = clean_target(target)
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM scans WHERE target = ?", (cleaned,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return JSONResponse(status_code=404, content={"error": "Scan not found"})
        
        scan_id = row[0]
        cursor.execute("SELECT category, data FROM scan_data WHERE scan_id = ?", (scan_id,))
        data_rows = cursor.fetchall()
        conn.close()
        
        # Group by category
        results = {}
        for cat, data_str in data_rows:
            if cat not in results:
                results[cat] = []
            results[cat].append(json.loads(data_str))
            
        return {"target": cleaned, "results": results}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.delete("/api/scan/{target}")
async def delete_scan(target: str):
    cleaned = clean_target(target)
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("DELETE FROM scans WHERE target = ?", (cleaned,))
        conn.commit()
        conn.close()
        return {"status": "success", "message": f"Deleted history for {cleaned}"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/", response_class=HTMLResponse)
async def get():
    index_path = BASE_DIR / "templates" / "index.html"
    with open(index_path, "r") as f:
        return HTMLResponse(content=f.read())


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                action = message.get("action")
                raw_target = message.get("target", "").strip()

                if action == "start":
                    cleaned_target = clean_target(raw_target)
                    # Robust target validation to prevent command injection
                    if validate_target(cleaned_target):
                        scan_id = start_db_scan(cleaned_target)
                        db_ws = DatabaseSavingWebSocket(websocket, scan_id)
                        await websocket.send_json({"type": "scan_start", "target": cleaned_target})

                        modules = [
                            module1_domain_scraping(db_ws, cleaned_target),
                            module2_certificate_transparency(db_ws, cleaned_target),
                            module3_passive_dns(db_ws, cleaned_target),
                            module4_historical_repos(db_ws, cleaned_target),
                            module5_code_leakage(db_ws, cleaned_target),
                            module6_human_intelligence(db_ws, cleaned_target),
                            module7_firewall_detection(db_ws, cleaned_target),
                        ]
                        await asyncio.gather(*modules, return_exceptions=True)
                        await websocket.send_json({"type": "scan_complete"})
                    else:
                        await websocket.send_json({"type": "error", "message": "Invalid target domain or IP format"})
            except Exception as e:
                await websocket.send_json({"type": "error", "message": str(e)})
    except Exception:
        pass


def main():
    import webbrowser
    import threading
    import time

    def open_browser():
        time.sleep(1.5)
        webbrowser.open("http://localhost:8000")

    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
