# if using Jupyter Notebooks or CoLab, use these magic commands instead of subprocess.check_call
# !pip install requests
# !pip install dnspython
# !pip install impacket

import subprocess
subprocess.check_call (['pip', 'install', 'requests'])
subprocess.check_call (['pip', 'install', 'dnspython'])
subprocess.check_call (['pip', 'install', 'impacket'])

import dns.resolver
import requests
import socket
import smtplib
import ssl

# Scan open ports and trigger respective checks
def port_scanner(target_ip):
    ports = {
        25: "SMTP (Simple Mail Transfer Protocol) - used for email routing.",
        53: "DNS (Domain Name System) - used for domain name resolution.",
        80: "HTTP (HyperText Transfer Protocol) - used for web traffic.",
        443: "HTTPS (HyperText Transfer Protocol using SSL/TLS) - used for secure web traffic.",
        445: "SMB (Server Message Block) - used for file sharing in Windows networks."
    }
    
    open_ports = []
    
    # Validate IP address format
    try:
        socket.inet_aton(target_ip)
    except socket.error:
        print(f"Invalid IP address format: {target_ip}")
        return

    # Scan the specified ports
    for port, description in ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append((port, description))
        sock.close()

    # Display results and handle additional logic for open ports
    if open_ports:
        print(f"Open ports on {target_ip}:")
        for port, description in open_ports:
            print(f"Port {port}: {description}")
            
            # Trigger specific checks based on the open port
            if port == 445:
                enumerate_shares(target_ip)
            elif port == 25:
                check_smtp(target_ip)
            elif port == 53:
                check_dns(target_ip)
            elif port == 80:
                check_http(target_ip)
            elif port == 443:
                check_https(target_ip)
                check_https_certificate(target_ip)
    else:
        print(f"No open ports found on {target_ip} (ports: {list(ports.keys())}).")


# Check SMTP service
def check_smtp(target_ip):
    try:
        server = smtplib.SMTP(target_ip, 25, timeout=10)
        server.ehlo()
        print(f"SMTP service is responsive on {target_ip}.")
        server.quit()
    except Exception as e:
        print(f"Error connecting to SMTP on {target_ip}: {e}")


# Check DNS service
def check_dns(target_ip):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [target_ip]
        answer = resolver.resolve("google.com", "A")
        print(f"DNS service is responsive on {target_ip}. Resolved google.com to {answer[0]}")
    except Exception as e:
        print(f"Error querying DNS on {target_ip}: {e}")


# Check HTTP service
def check_http(target_ip):
    try:
        response = requests.get(f"http://{target_ip}", timeout=5)
        print(f"HTTP service is responsive on {target_ip}. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error connecting to HTTP on {target_ip}: {e}")

def check_https(target_ip):
    try:
      response = requests.get(f"https://{target_ip}", timeout=5)
      print(f"HTTPS service is responsive on {target_ip}. Status code: {response.status_code}")
    except Exception as e:
      print(f"Error connecting to HTTPS on {target_ip}: {e}")

def check_https_certificate(target_ip):
    try:
      context = ssl.create_default_context()
      conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=target_ip)
      conn.settimeout(5)
      conn.connect((target_ip, 443))

      cert = conn.getpeercert()
      issuer = dict(x[0] for x in cert['issuer'])
      subject_alt_names = cert.get('subjectAltName', [])
      expiration_date = cert['notAfter']
      conn.close()

      print(f"\nCertificate details for {target_ip}:")
      print(f"\tCertificate Authority (Issuer): {issuer.get('organizationName', 'Unknown')}")
      print(f"\tSubject Alternative Names (SANs): {[san[1] for san in subject_alt_names]}")
      print(f"\tExpiration Date: {expiration_date}")

    except Exception as e:
      print(f"Error retrieving HTTPS certificate from {target_ip}: {e}")


# Enumerate SMB shares
def enumerate_shares(target_ip):
    try:
        result = subprocess.run(['smbclient', '-L', f'\\\\{target_ip}', '--no-pass'], 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            print(f"Shares available on {target_ip}:\n")
            print(result.stdout)
        else:
            print(f"Error connecting to SMB on {target_ip}: {result.stderr}")
    except Exception as e:
        print(f"Error enumerating SMB shares: {e}")


if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")
    port_scanner(target_ip)
