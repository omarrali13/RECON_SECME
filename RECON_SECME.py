import socket
import whois
import requests
import ssl
import subprocess
import sys
from datetime import datetime
from termcolor import colored

# 🎯 Fancy Banner
def banner(domain, ip):
    print("\n" + "="*60)
    print(colored(f"🌐 DOMAIN RECON REPORT", "cyan", attrs=["bold"]))
    print("="*60)
    print(f"🧾 Target Domain: {colored(domain, 'yellow', attrs=['bold'])}")
    print(f"🔍 Resolved IP : {colored(ip, 'green', attrs=['bold'])}")
    print("="*60 + "\n")

# 1. 🌍 Resolve Domain
def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        print(f"❌ Resolution failed: {e}")
        return None

# 2. 📜 WHOIS
def whois_lookup(domain):
    print(colored("\n📜 WHOIS Lookup", "cyan", attrs=["bold"]))
    print("-"*50)
    try:
        w = whois.whois(domain)
        print(f"📅 Domain Created: {w.creation_date}")
        print(f"📆 Expires On   : {w.expiration_date}")
        print(f"👤 Registrant   : {w.name or 'N/A'}")
        print(f"📩 Email        : {w.emails or 'N/A'}")
        print(f"🏢 Registrar    : {w.registrar}")
    except Exception as e:
        print(f"❌ WHOIS failed: {e}")

# 3. 📡 Subdomain Finder
def subdomain_scan(domain):
    print(colored("\n📡 Subdomain Enumeration", "cyan", attrs=["bold"]))
    print("-"*50)
    wordlist = ["www", "mail", "ftp", "blog", "test", "api", "dev"]
    found = []
    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            print(f"✅ {subdomain}")
            found.append(subdomain)
        except:
            pass
    if not found:
        print("❌ No common subdomains found.")

# 4. 🛰️ Port Scanner
def port_scan(ip):
    print(colored("\n🛰️ Port Scan", "cyan", attrs=["bold"]))
    print("-"*50)
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 3306, 3389, 8080]
    open_ports = []
    for port in common_ports:
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"🔓 Port {port} is OPEN")
                open_ports.append(port)
            sock.close()
        except:
            pass
    if not open_ports:
        print("❌ No open common ports detected.")
    return open_ports

# 5. 🧪 Tech Stack (Headers)
def tech_headers(domain):
    print(colored("\n🧪 HTTP Header Analysis", "cyan", attrs=["bold"]))
    print("-"*50)
    try:
        r = requests.get(f"http://{domain}", timeout=3)
        for k, v in r.headers.items():
            print(f"🔧 {k}: {v}")
    except Exception as e:
        print(f"❌ Header scan failed: {e}")

# 6. 🔐 SSL Info
def ssl_info(domain):
    print(colored("\n🔐 SSL Certificate Info", "cyan", attrs=["bold"]))
    print("-"*50)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(f"📅 Issued On : {cert.get('notBefore')}")
                print(f"📆 Expires On: {cert.get('notAfter')}")
                print(f"🔐 Issuer    : {cert.get('issuer')}")
    except Exception as e:
        print(f"❌ SSL info failed: {e}")

# 7. 🧭 Reverse IP
def reverse_ip(ip):
    print(colored("\n🧭 Reverse IP Lookup", "cyan", attrs=["bold"]))
    print("-"*50)
    try:
        result = subprocess.check_output(f"curl -s https://api.hackertarget.com/reverseiplookup/?q={ip}", shell=True)
        output = result.decode()
        if "No records found" in output:
            print("❌ No other domains found on this IP.")
        else:
            print(output)
    except Exception as e:
        print(f"❌ Reverse IP failed: {e}")

# 8. 🛡️ Vulnerability Awareness
def vuln_check(ip, open_ports):
    print(colored("\n🛡️ Vulnerability Awareness", "red", attrs=["bold"]))
    print("-"*50)

    known_vulns = {
        21:  ("FTP", "Anonymous login, credential reuse, brute force 🔐"),
        22:  ("SSH", "Weak passwords, outdated keys, brute force 💀"),
        23:  ("Telnet", "Unencrypted login, default creds 😱"),
        80:  ("HTTP", "XSS, SQLi, Dir Traversal, outdated CMS 🕳️"),
        443: ("HTTPS", "SSL misconfigs, heartbleed (old) 💔"),
        445: ("SMB", "EternalBlue, SMBv1 vulnerabilities 🧨"),
        3306:("MySQL", "Weak root creds, SQL injection 🔥"),
        3389:("RDP", "BlueKeep, RDP brute-force 🚪💣"),
        8080:("Alt HTTP", "Exposed dev panels, Tomcat exploits 🧬"),
    }

    if not open_ports:
        print("❌ No ports to scan for vulns.")
        return

    for port in open_ports:
        if port in known_vulns:
            service, vuln = known_vulns[port]
            print(f"⚠️  Port {port} ({service}) → {colored(vuln, 'yellow')}")
        else:
            print(f"🔎 Port {port}: No known signature, consider deeper scan 🕵️‍♂️")

# 🌐 Run All
def recon_main():
    domain = input("🔎 Enter domain to scan: ").strip()
    ip = resolve_domain(domain)
    if not ip:
        return
    banner(domain, ip)
    whois_lookup(domain)
    subdomain_scan(domain)
    open_ports = port_scan(ip)
    vuln_check(ip, open_ports)
    tech_headers(domain)
    ssl_info(domain)
    reverse_ip(ip)

if __name__ == "__main__":
    try:
        from termcolor import colored
    except:
        print("⚠️ Installing required module: termcolor")
        subprocess.call([sys.executable, "-m", "pip", "install", "termcolor"])
        from termcolor import colored
    recon_main()
# Note: This script is for educational purposes only. Unauthorized use of these techniques is illegal and unethical.
# Ensure you have the required libraries installed. 
# Made By THERAMO