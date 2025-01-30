import pyfiglet
import socket
import requests
import whois
import json
from termcolor import colored
import dns.resolver
from pythonping import ping

# Display a fancy banner
banner = colored(pyfiglet.figlet_format("IP Matrix"), 'blue')
print(banner)


def resolve_domain_to_ip(domain_name):
    """Resolve a domain name to its IP address."""
    try:
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror:
        return "Error: Unable to resolve domain."


def resolve_ip_to_domain(ip_address):
    """Resolve an IP address to its domain name."""
    try:
        host = socket.gethostbyaddr(ip_address)
        return host[0]
    except socket.herror:
        return "Error: Unable to resolve IP."


def geolocate_ip(ip_address):
    """Fetch geolocation data for an IP address using ip-api.com."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        if data['status'] == 'success':
            return {
                "Country": data['country'],
                "Region": data['regionName'],
                "City": data['city'],
                "ISP": data['isp'],
                "Latitude": data['lat'],
                "Longitude": data['lon'],
            }
        else:
            return "Error: Unable to fetch geolocation data."
    except Exception as e:
        return f"Error: {str(e)}"


def whois_lookup(domain_name):
    """Fetch Whois data for a domain."""
    try:
        domain_info = whois.whois(domain_name)
        return {
            "Domain Name": domain_info.domain_name,
            "Registrar": domain_info.registrar,
            "Creation Date": str(domain_info.creation_date),
            "Expiration Date": str(domain_info.expiration_date),
            "Name Servers": domain_info.name_servers,
        }
    except Exception as e:
        return f"Error: {str(e)}"


def ping_test(target):
    """Ping a domain or IP to check connectivity."""
    try:
        result = ping(target, count=4, verbose=True)
        return f"Ping results:\n{result}"
    except Exception as e:
        return f"Error: Unable to ping {target}. {str(e)}"


def port_scan(ip, start_port=1, end_port=1024):
    """Scan for open ports on a given IP address."""
    open_ports = []
    try:
        for port in range(start_port, end_port + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        return open_ports if open_ports else "No open ports found."
    except Exception as e:
        return f"Error: {str(e)}"


def dns_lookup(domain_name):
    """Fetch DNS records for a domain."""
    try:
        records = dns.resolver.resolve(domain_name, 'A')
        return [str(r) for r in records]
    except Exception as e:
        return f"Error: {str(e)}"


def save_results(data, file_format="txt"):
    """Save results to a file in .txt or .json format."""
    file_name = f"results.{file_format}"
    try:
        if file_format == "txt":
            with open(file_name, "w") as file:
                file.write(str(data))
        elif file_format == "json":
            with open(file_name, "w") as file:
                json.dump(data, file, indent=4)
        print(colored(f"Results saved to {file_name}", 'green'))
    except Exception as e:
        print(colored(f"Error saving results: {str(e)}", 'yellow'))


def main():
    """Main menu for the tool."""
    while True:
        print("\nSelect an option:")
        print("1. Resolve Domain to IP")
        print("2. Resolve IP to Domain")
        print("3. Geolocate an IP")
        print("4. Perform Whois Lookup")
        print("5. Ping Test")
        print("6. Port Scan")
        print("7. DNS Lookup")
        print("8. Exit")
       
        choice = input("\nEnter your choice (1-8): ").strip()
        
        if choice == "1":
            domain = input("Enter the domain name: ").strip()
            result = resolve_domain_to_ip(domain)
            print(f"\nResolved IP: {result}")
            save_results(f"Domain: {domain}\nResolved IP: {result}")
        
        elif choice == "2":
            ip = input("Enter the IP address: ").strip()
            result = resolve_ip_to_domain(ip)
            print(f"\nResolved Domain: {result}")
            save_results(f"IP: {ip}\nResolved Domain: {result}")
        
        elif choice == "3":
            ip = input("Enter the IP address: ").strip()
            result = geolocate_ip(ip)
            print("\nGeolocation Data:")
            print(result)
            save_results(result, "json")
        
        elif choice == "4":
            domain = input("Enter the domain name: ").strip()
            result = whois_lookup(domain)
            print("\nWhois Data:")
            print(result)
            save_results(result, "json")
        
        elif choice == "5":
            target = input("Enter the domain or IP to ping: ").strip()
            result = ping_test(target)
            print("\nPing Test Results:")
            print(result)
        
        elif choice == "6":
            ip = input("Enter the IP address to scan: ").strip()
            start_port = int(input("Enter the start port: ").strip())
            end_port = int(input("Enter the end port: ").strip())
            result = port_scan(ip, start_port, end_port)
            print("\nPort Scan Results:")
            print(result)
        
        elif choice == "7":
            domain = input("Enter the domain name: ").strip()
            result = dns_lookup(domain)
            print("\nDNS Lookup Results:")
            print(result)
            save_results(result, "json")
        
        elif choice == "8":
            print(colored("\nExiting the tool. Goodbye!", 'cyan'))
            break
        
        else:
            print(colored("\nInvalid choice. Please select a valid option.", 'yellow'))


if __name__ == "__main__":
    main()
