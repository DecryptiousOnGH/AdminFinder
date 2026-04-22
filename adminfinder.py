#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdminFinder
Author: Decryptious_ on Discord / Punchborn on IG
A cross-platform reconnaissance tool for IP resolution and admin panel discovery.
For authorized security testing only.
"""

import sys
import os
import socket
import subprocess
import platform
import argparse
import threading
import time
import json
import random
from urllib.parse import urljoin, urlparse
from datetime import datetime

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Missing dependency: requests")
    print("[*] Install: pip install -r requirements.txt")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class DummyFore:
        def __getattr__(self, name): return ''
    class DummyStyle:
        def __getattr__(self, name): return ''
    Fore = DummyFore()
    Style = DummyStyle()

# ── BANNER ──
BANNER = f"""
{Fore.CYAN}    _       _           _  _____ _           _           
   / \\   __| |_ __ ___ (_)|  ___(_)_ __   __| | ___ _ __ 
  / _ \\ / _` | '_ ` _ \\| || |_  | | '_ \\ / _` |/ _ \\ '__|
 / ___ \\ (_| | | | | | | ||  _| | | | | | (_| |  __/ |   
/_/   \\_\\__,_|_| |_| |_|_|_|   |_|_| |_|\\__,_|\\___|_|   
{Style.RESET_ALL}
{Fore.YELLOW}[*] Author: Decryptious_ on Discord / Punchborn on IG
[*] Cross-Platform Admin Panel Discovery Tool
[*] For authorized security testing only{Style.RESET_ALL}
"""

# ── USER AGENTS ──
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
]

class AdminFinder:
    def __init__(self, target, threads=20, timeout=10, wordlist=None, output=None, verbose=False):
        self.target = self._normalize_url(target)
        self.domain = urlparse(self.target).netloc
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.output_file = output
        self.found = []
        self.checked = 0
        self.total = 0
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        
        self.wordlist = self._load_wordlist(wordlist)
        self.total = len(self.wordlist)
        
    def _normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _load_wordlist(self, filepath):
        default_paths = [
            "admin", "administrator", "admin1", "admin2", "admin3", "admin4", "admin5",
            "usuarios", "usuario", "moderator", "webadmin", "adminarea", "bb-admin",
            "adminLogin", "admin_area", "panel-administracion", "instadmin", "memberadmin",
            "administratorlogin", "adm", "admin/account.php", "admin/index.php",
            "admin/login.php", "admin/admin.php", "admin/account.html", "admin/index.html",
            "admin/login.html", "admin/admin.html", "admin/home.php", "admin/home.html",
            "admin/controlpanel.html", "admin/cp.html", "admin/cp.php", "administrator/index.php",
            "administrator/login.php", "administrator/account.php", "administrator/index.html",
            "administrator/login.html", "administrator/account.html", "administrator/home.html",
            "login.php", "login.html", "signin.php", "signin.html", "wp-login.php", "wp-admin",
            "wp-admin/admin.php", "cms", "panel", "cpanel", "control", "controlpanel",
            "manager", "management", "webmaster", "root", "secure", "backend", "backoffice",
            "dashboard", "admin.php", "admin.asp", "admin.aspx", "admin.jsp", "admin.cgi",
            "admin.pl", "admin.py", "admin.rb", "admin/login", "admin/signin", "admin/auth",
            "account/login", "auth/login", "auth/admin", "private", "staff", "employee",
            "portal", "console", "phpmyadmin", "pma", "dbadmin", "sqladmin", "mysql",
            "myadmin", "phpMyAdmin", "adminer.php", "adminer", "setup", "install",
            "configure", "config", "settings", "api/admin", "api/v1/admin", "api/v2/admin",
            "manage", "management/login", "management/signin", "sysadmin", "sys-admin",
            "system/login", "system/admin", "control/login", "cp/login", "cpanel/login",
            "whm", "whmcs", "billing", "billing/login", "support", "support/login",
            "helpdesk", "helpdesk/login", "tickets", "tickets/login", "clientarea",
            "clientarea/login", "members/login", "users/login", "accounts/login",
            "admin/account/login", "admin/account/signin", "admin/dashboard",
            "administrator/dashboard", "administrator/panel", "admin/panel",
            "admin/secure", "admin/private", "admin/portal", "admin/control",
            "admin/manage", "admin/management", "admin/user", "admin/users",
            "admin/member", "admin/members", "admin/staff", "admin/employee",
            "portal/login", "portal/signin", "portal/auth", "portal/admin",
            "portal/dashboard", "member/login", "member/signin", "member/auth",
            "user/login", "user/signin", "user/auth", "client/login", "client/signin",
            "staff/login", "staff/signin", "staff/auth", "employee/login", "employee/signin",
            "manager/login", "manager/signin", "manager/auth", "webmaster/login",
            "webmaster/signin", "webmaster/auth", "hosting/login", "hosting/signin",
            "server/login", "server/signin", "system/login", "system/signin",
            "sys/login", "sys/signin", "sys/auth", "sys/admin", "sysadmin/login",
            "sysadmin/signin", "sysadmin/auth", "sysadmin/admin", "control/signin",
            "control/auth", "control/admin", "controlpanel/login", "controlpanel/signin",
            "controlpanel/auth", "controlpanel/admin", "panel/login", "panel/signin",
            "panel/auth", "panel/admin", "cp/signin", "cp/auth", "cp/admin",
            "cpanel/signin", "cpanel/auth", "cpanel/admin", "whm/login", "whm/signin",
            "whm/auth", "whm/admin", "whmcs/login", "whmcs/signin", "whmcs/auth",
            "whmcs/admin", "billing/signin", "billing/auth", "billing/admin",
            "support/signin", "support/auth", "support/admin", "helpdesk/signin",
            "helpdesk/auth", "helpdesk/admin", "tickets/signin", "tickets/auth",
            "tickets/admin", "clientarea/signin", "clientarea/auth", "clientarea/admin",
            "members/signin", "members/auth", "members/admin", "users/signin",
            "users/auth", "users/admin", "accounts/signin", "accounts/auth", "accounts/admin",
            "login", "logon", "signin", "signon", "authenticate", "authentication",
            "auth", "authorization", "access", "entry", "gate", "gateway",
            "admin/account", "admin/auth", "admin/signin", "admin/welcome",
            "admin/default", "admin/main", "admin/home", "administrator/account",
            "administrator/auth", "administrator/signin", "administrator/welcome",
            "administrator/default", "administrator/main", "administrator/home",
            "administrator/user", "administrator/users", "administrator/member",
            "administrator/members", "administrator/staff", "administrator/employee",
            "administrator/portal", "administrator/secure", "administrator/private",
            "administrator/control", "administrator/manage", "administrator/management",
        ]
        
        if filepath and os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"{Fore.CYAN}[*] Loaded {len(paths)} paths from custom wordlist{Style.RESET_ALL}")
            return paths
        return default_paths
    
    def resolve_ip(self):
        """Method 1: Socket DNS resolution (fast, works everywhere)"""
        print(f"\n{Fore.CYAN}[*] Resolving target IP...{Style.RESET_ALL}")
        try:
            ip = socket.gethostbyname(self.domain)
            print(f"{Fore.GREEN}[+] IP Address (Socket): {ip}{Style.RESET_ALL}")
            return ip
        except socket.gaierror as e:
            print(f"{Fore.RED}[-] Socket resolution failed: {e}{Style.RESET_ALL}")
            return None
    
    def system_ping(self):
        """Method 2: Native OS ping command (cross-platform)"""
        print(f"{Fore.CYAN}[*] Executing system ping...{Style.RESET_ALL}")
        system = platform.system().lower()
        
        try:
            if system == "windows":
                cmd = ["ping", "-n", "4", self.domain]
            else:
                cmd = ["ping", "-c", "4", self.domain]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"{Fore.GREEN}[+] Ping successful ({system}){Style.RESET_ALL}")
                output = result.stdout
                if system == "windows":
                    if "[" in output and "]" in output:
                        ip = output.split("[")[1].split("]")[0]
                    else:
                        ip = output.split()[-1].strip(":")
                else:
                    lines = output.split('\n')
                    if lines:
                        first_line = lines[0]
                        if "(" in first_line and ")" in first_line:
                            ip = first_line.split("(")[1].split(")")[0]
                        else:
                            ip = first_line.split()[1]
                
                print(f"{Fore.GREEN}[+] IP Address (Ping): {ip}{Style.RESET_ALL}")
                return ip
            else:
                print(f"{Fore.YELLOW}[!] Ping returned non-zero exit code{Style.RESET_ALL}")
                return None
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[!] Ping timed out{Style.RESET_ALL}")
            return None
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[!] Ping command not found on system{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Ping error: {e}{Style.RESET_ALL}")
            return None
    
    def _check_path(self, path):
        url = urljoin(self.target + "/", path)
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            status = resp.status_code
            
            with self.lock:
                self.checked += 1
                if self.checked % 50 == 0 or self.checked == self.total:
                    print(f"{Fore.CYAN}[*] Progress: {self.checked}/{self.total} checked{Style.RESET_ALL}", end='\r')
            
            is_interesting = False
            indicators = []
            
            if status in [200, 201]:
                content = resp.text.lower()
                admin_keywords = ['login', 'password', 'username', 'admin', 'sign in', 'signin', 
                                'authentication', 'dashboard', 'control panel', 'wp-submit',
                                'log in', 'passwd', 'user', 'email', 'remember me']
                for keyword in admin_keywords:
                    if keyword in content:
                        indicators.append(keyword)
                if indicators:
                    is_interesting = True
            elif status == 403:
                is_interesting = True
                indicators.append("Forbidden")
            elif status == 401:
                is_interesting = True
                indicators.append("Unauthorized")
            
            if is_interesting:
                with self.lock:
                    result = {
                        "url": url,
                        "status": status,
                        "indicators": indicators,
                        "length": len(resp.content),
                        "redirect": resp.url if resp.url != url else None
                    }
                    self.found.append(result)
                    
                    status_color = Fore.GREEN if status == 200 else Fore.YELLOW
                    print(f"\n{status_color}[{status}] {url}{Style.RESET_ALL}")
                    if indicators:
                        print(f"    {Fore.MAGENTA}Indicators: {', '.join(indicators)}{Style.RESET_ALL}")
                    print(f"    {Fore.CYAN}Size: {len(resp.content)} bytes{Style.RESET_ALL}")
                    
        except requests.exceptions.Timeout:
            if self.verbose:
                with self.lock:
                    print(f"{Fore.YELLOW}[TIMEOUT] {url}{Style.RESET_ALL}")
        except requests.exceptions.ConnectionError:
            if self.verbose:
                with self.lock:
                    print(f"{Fore.YELLOW}[CONNERR] {url}{Style.RESET_ALL}")
        except Exception as e:
            if self.verbose:
                with self.lock:
                    print(f"{Fore.RED}[ERROR] {url} - {e}{Style.RESET_ALL}")
    
    def scan(self):
        print(f"\n{Fore.CYAN}[*] Starting admin panel scan{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target: {self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Threads: {self.threads}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Wordlist size: {self.total} paths{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Timeout: {self.timeout}s{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop early{Style.RESET_ALL}\n")
        
        start_time = time.time()
        
        try:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(self._check_path, self.wordlist)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        
        elapsed = time.time() - start_time
        
        print(f"\n{Fore.CYAN}[*] Scan completed in {elapsed:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Checked: {self.checked}/{self.total}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Potential admin panels found: {len(self.found)}{Style.RESET_ALL}")
        
        if self.found:
            print(f"\n{Fore.GREEN}[+] Results:{Style.RESET_ALL}")
            for item in self.found:
                status_color = Fore.GREEN if item['status'] == 200 else Fore.YELLOW
                print(f"  {status_color}[{item['status']}] {item['url']}{Style.RESET_ALL}")
        
        self._save_results(elapsed)
    
    def _save_results(self, elapsed):
        if not self.output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_file = f"adminfinder_results_{self.domain}_{timestamp}.txt"
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("AdminFinder Scan Report\n")
            f.write("Author: Decryptious_ on Discord / Punchborn on IG\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Domain: {self.domain}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Platform: {platform.system()} {platform.release()}\n")
            f.write(f"Threads: {self.threads}\n")
            f.write(f"Timeout: {self.timeout}s\n")
            f.write(f"Wordlist: {self.total} paths\n")
            f.write(f"Checked: {self.checked}\n")
            f.write(f"Found: {len(self.found)}\n")
            f.write(f"Duration: {elapsed:.2f}s\n")
            f.write("=" * 60 + "\n\n")
            
            if self.found:
                f.write("[+] DISCOVERED ADMIN PANELS:\n")
                for item in self.found:
                    f.write(f"\nStatus: {item['status']}\n")
                    f.write(f"URL: {item['url']}\n")
                    f.write(f"Size: {item['length']} bytes\n")
                    f.write(f"Indicators: {', '.join(item['indicators'])}\n")
                    if item['redirect']:
                        f.write(f"Redirect: {item['redirect']}\n")
                    f.write("-" * 40 + "\n")
            else:
                f.write("[-] No admin panels discovered.\n")
        
        json_file = self.output_file.replace('.txt', '.json')
        report = {
            "tool": "AdminFinder",
            "author": "Decryptious_ on Discord / Punchborn on IG",
            "target": self.target,
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "platform": f"{platform.system()} {platform.release()}",
            "config": {
                "threads": self.threads,
                "timeout": self.timeout,
                "wordlist_size": self.total
            },
            "statistics": {
                "checked": self.checked,
                "found": len(self.found),
                "duration_seconds": round(elapsed, 2)
            },
            "results": self.found
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Text report saved: {self.output_file}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] JSON report saved: {json_file}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="AdminFinder - Cross-platform admin panel discovery tool",
        epilog="Example: python3 adminfinder.py -u https://example.com -t 50"
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file path")
    parser.add_argument("-o", "--output", help="Output file name")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show errors/timeouts)")
    parser.add_argument("--no-ping", action="store_true", help="Skip system ping, use DNS only")
    parser.add_argument("--no-banner", action="store_true", help="Hide banner")
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print(BANNER)
    
    finder = AdminFinder(
        target=args.url,
        threads=args.threads,
        timeout=args.timeout,
        wordlist=args.wordlist,
        output=args.output,
        verbose=args.verbose
    )
    
    ip_socket = finder.resolve_ip()
    
    ip_ping = None
    if not args.no_ping:
        ip_ping = finder.system_ping()
    
    if not ip_socket and not ip_ping:
        print(f"{Fore.RED}[-] Could not resolve target. Exiting.{Style.RESET_ALL}")
        sys.exit(1)
    
    finder.scan()


if __name__ == "__main__":
    main()