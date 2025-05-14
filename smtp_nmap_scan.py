import nmap

SMTP_PORTS = "25,465,587,2525"

def scan_smtp_ports(target):
    nm = nmap.PortScanner()
    print(f"[+] Scanning {target} for SMTP ports: {SMTP_PORTS}")
    
    nm.scan(hosts=target, arguments=f'-p {SMTP_PORTS} -sV')

    if target in nm.all_hosts():
        for proto in nm[target].all_protocols():
            lport = nm[target][proto].keys()
            for port in sorted(lport):
                state = nm[target][proto][port]['state']
                name = nm[target][proto][port].get('name', '')
                product = nm[target][proto][port].get('product', '')
                version = nm[target][proto][port].get('version', '')
                print(f"[+] Port {port}/tcp is {state} - {product} {version} ({name})")
    else:
        print("[-] Host seems down or unresponsive.")

if __name__ == "__main__":
    target = input("Enter the target IP or hostname: ").strip()
    scan_smtp_ports(target)
