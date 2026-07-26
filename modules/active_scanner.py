"""
modules/active_scanner.py - Fallback Active TCP Port Scanner

This module performs highly concurrent asynchronous TCP connections to a target IP
to check for open ports. Used as a fallback when Shodan API is unavailable.
"""

import asyncio

# A list of common top ports to scan
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
]

async def check_port(ip: str, port: int, timeout: float = 1.5) -> int:
    """Attempts to connect to a specific port on the target IP."""
    try:
        # Use asyncio.wait_for to enforce timeout on the open_connection call
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), # It will attempt a three way handshake (syn, syn-ack, ack).
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None

async def scan_ip_active(ip: str, ports: list = TOP_PORTS, concurrency: int = 50) -> dict:
    """Scans an IP address for open ports from the provided list concurrently."""
    semaphore = asyncio.Semaphore(concurrency)
    
    # Limit the number of concurrent connections
    async def sem_check_port(port):
        async with semaphore:
            return await check_port(ip, port)
            
    tasks = [sem_check_port(p) for p in ports]
    results = await asyncio.gather(*tasks)
    
    open_ports = [port for port in results if port is not None]
    
    return {
        "ip": ip,
        "ports": open_ports,
        "services": [], # Fallback scanner does not perform service banner grabbing
        "vulns": []     # Fallback scanner does not check CVEs
    }

async def run_active_scans(ips: set) -> dict:
    """Scans multiple IP addresses concurrently."""
    print(f"\n[*] Starting Fallback Active Port Scan on {len(ips)} IPs for Top {len(TOP_PORTS)} ports...")
    
    results = {}
    for i, ip in enumerate(ips, 1):
        print(f"[*] Scanning ({i}/{len(ips)}): {ip}")
        result = await scan_ip_active(ip)
        results[ip] = result
        
    print("[+] Active bulk scan completed.")
    return results
