"""
modules/resolver.py - Asynchronous DNS Resolution Module

This module performs concurrent, asynchronous DNS lookups using Python's asyncio event loop 
and getaddrinfo method to resolve subdomains to their IPv4 addresses without blocking the program.
"""

import asyncio
import socket
import random
import string

async def resolve_subdomain(subdomain: str, semaphore: asyncio.Semaphore) -> tuple: # Resolves subdomains to IPs
    async with semaphore: # Limits concurrent connections to avoid too many requests
        try:
            loop = asyncio.get_running_loop() # For sync getaddrinfo to async
            addrinfo = await loop.getaddrinfo( # DNS Resolver Function
                subdomain,
                None, # No port
                family=socket.AF_INET, # Only IPv4 addresses
                type=socket.SOCK_STREAM # Only TCP protocol
            )
            ips = set() # Filters duplicate IP addresses
            for res in addrinfo:
                ips.add(res[4][0])
            return (subdomain, ips) # Matched Subdomain with IP Addresses
        except socket.gaierror:
            print(f"Error: Could not resolve domain: {subdomain}")
            return (subdomain, set())

async def resolve_subdomains_concurrently(subdomains: list, max_concurrency: int = 50) -> dict:
    semaphore = asyncio.Semaphore(max_concurrency)

    tasks = [resolve_subdomain(subdomain, semaphore) for subdomain in subdomains] # Create tasks for each subdomain
    results = await asyncio.gather(*tasks, return_exceptions=True) # Wait for all tasks to complete
    
    resolved_map = {} # Dictionary to store resolved subdomains
    for res in results:
        # Pass when an Exception occurs
        if isinstance(res, Exception):
            continue
        # Append results to resolved_map if IP is found
        subdomain, ips = res
        if ips:
            resolved_map[subdomain] = ips
            
    return resolved_map

async def check_wildcard(domain: str) -> bool:
    """
    Detects if the domain has a wildcard DNS record by resolving a random subdomain.
    """

    # Generate a random 12-character subdomain
    random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    test_domain = f"{random_sub}.{domain}"
    
    semaphore = asyncio.Semaphore(1)
    _, ips = await resolve_subdomain(test_domain, semaphore)
    
    return len(ips) > 0