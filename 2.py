#!/usr/bin/env python3
import subprocess
import os
import sys
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs

def print_banner():
    banner = r"""
     ____        _     _           _     
    / ___| _   _| |__ | |__  _   _| |__  
    \___ \| | | | '_ \| '_ \| | | | '_ \ 
     ___) | |_| | |_) | |_) | |_| | | | |
    |____/ \__,_|_.__/|_.__/ \__,_|_| |_|
    Subdomain Collector (Assetfinder + Subfinder + Amass + GAU)
    """
    print(banner)
    print(f"[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

def check_tools():
    """Verify required tools are installed."""
    tools = {
        'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest',
        'subfinder': 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
        'amass': 'go install github.com/owasp-amass/amass/v3/...@latest',
        'gau': 'go install github.com/lc/gau/v2/cmd/gau@latest'
    }
    
    missing = []
    for tool, install_cmd in tools.items():
        if not subprocess.run(f"which {tool}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
            missing.append((tool, install_cmd))
    
    if missing:
        print("[-] Missing required tools:")
        for tool, install_cmd in missing:
            print(f"    {tool} (Install: {install_cmd})")
        print("\n[!] Install missing tools and try again.")
        sys.exit(1)

def run_command(command, tool_name, timeout=1800):
    """Run a shell command with improved error handling."""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            check=False,
            timeout=timeout
        )

        if result.returncode != 0:
            print(f"    [!] {tool_name} failed (Code: {result.returncode})")
            if result.stderr.strip():
                print(f"        Error: {result.stderr.strip()}")
            return []
        
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except subprocess.TimeoutExpired:
        print(f"    [!] {tool_name} timed out after {timeout} seconds")
        return []
    except Exception as e:
        print(f"    [!] Unexpected error with {tool_name}: {str(e)}")
        return []

def save_to_file(data, filename):
    """Save a list of lines to a file."""
    try:
        with open(filename, 'w') as f:
            f.write("\n".join(data))
        print(f"    [✓] Saved {len(data)} entries to {os.path.abspath(filename)}")
    except IOError as e:
        print(f"    [!] Error saving to file {filename}: {e}")

def load_file(filename):
    """Load lines from a file."""
    if not os.path.exists(filename):
        return []
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except IOError as e:
        print(f"    [!] Error loading file {filename}: {e}")
        return []

def merge_results(files):
    """Merge and deduplicate results from multiple files."""
    merged = set()
    for file in files:
        if os.path.exists(file):
            with open(file, 'r') as f:
                merged.update(line.strip() for line in f if line.strip())
    return sorted(merged)

def run_gau(domain):
    """Run GAU to fetch URLs and extract parameters."""
    print("\n[*] Running GAU to fetch URLs...")
    gau_cmd = f"gau {domain} --subs --threads 20"
    urls = run_command(gau_cmd, "GAU")
    
    if not urls:
        print("    [!] GAU returned no results")
        return set(), set()
    
    # Save raw URLs
    raw_urls_file = f"gau_urls_{domain}.txt"
    save_to_file(urls, raw_urls_file)
    
    # Extract unique parameters
    print("\n[*] Extracting unique parameters...")
    unique_params = set()
    unique_urls_with_params = set()
    
    for url in urls:
        try:
            parsed = urlparse(url)
            if parsed.query:
                unique_urls_with_params.add(url)
                params = parse_qs(parsed.query)
                unique_params.update(params.keys())
        except Exception as e:
            print(f"    [!] Error parsing URL {url}: {e}")
    
    return unique_urls_with_params, unique_params

def collect_subdomains(domain):
    """Main subdomain collection workflow."""
    print(f"[*] Target: {domain}\n")
    
    tools = {
        'assetfinder': f"assetfinder --subs-only {domain}",
        'subfinder': f"subfinder -d {domain} -silent",
        'amass': f"amass enum -passive -d {domain} -silent"
    }

    # Run all tools
    for name, cmd in tools.items():
        print(f"[*] Running {name}...")
        results = run_command(cmd, name)
        if results:
            save_to_file(results, f"{name}_subdomains.txt")
        else:
            print(f"    [!] No results from {name}")

    # Merge results
    print("\n[*] Merging results...")
    final_subdomains = merge_results([f"{name}_subdomains.txt" for name in tools.keys()])
    
    if not final_subdomains:
        print("\n[-] No subdomains found. Exiting.")
        sys.exit(1)

    # Save final output
    final_subdomains_file = f"final_subdomains_{domain}.txt"
    save_to_file(final_subdomains, final_subdomains_file)

    # Run GAU and extract parameters
    urls_with_params, unique_params = run_gau(domain)
    
    # Save parameter results
    if urls_with_params:
        param_urls_file = f"urls_with_params_{domain}.txt"
        save_to_file(sorted(urls_with_params), param_urls_file)
    
    if unique_params:
        params_file = f"unique_params_{domain}.txt"
        save_to_file(sorted(unique_params), params_file)

    # Summary
    print(f"\n[+] Final Results:")
    print(f"    Total unique subdomains: {len(final_subdomains)}")
    print(f"    Subdomains file: {os.path.abspath(final_subdomains_file)}")
    if urls_with_params:
        print(f"    URLs with parameters: {len(urls_with_params)}")
        print(f"    Parameter URLs file: {os.path.abspath(param_urls_file)}")
    if unique_params:
        print(f"    Unique parameters found: {len(unique_params)}")
        print(f"    Parameters file: {os.path.abspath(params_file)}")

if __name__ == "__main__":
    print_banner()
    check_tools()
    
    if len(sys.argv) != 2:
        print("Usage: python3 subdomain_collector.py <domain>")
        print("Example: python3 subdomain_collector.py example.com")
        sys.exit(1)

    target_domain = sys.argv[1].lower()
    collect_subdomains(target_domain)