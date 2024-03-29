import logging
from nmap import PortScanner

def print_scan_results(results: PortScanner):
    for host in results.all_hosts():
        # Check if host is up
        if results[host].state() == "up":
            open_ports = []
            # Check for TCP ports; similar blocks can be added for UDP or other protocols if needed
            for proto in results[host].all_protocols():
                open_ports.extend(results[host][proto].keys())
            # Formatting the output
            if open_ports:
                open_ports_str = ", ".join(map(str, open_ports))
                logging.info(f"Host: {host} - Open Ports: {open_ports_str}")
            else:
                logging.info(f"Host: {host} has no open ports.")

def print_vuln_details(results):
    for ip, details in results.items():
        print(f"IP: {ip}")
        # Check if there are vulnerabilities listed for the IP
        if 'vulns' in details:
            for product, vulns in details['vulns'].items():
                for cve, vuln_details in vulns.items():
                    # Attempting to find the port and product name for the CVE, along with severity score
                    port_info = find_port_with_product(details['ports'], product)
                    if port_info:
                        port, product_name = port_info
                        print(f"  Port: {port}, Product: {product_name}, CVE: {cve}, Severity Score: {vuln_details.get('severity_score', 'N/A')}")
                    else:
                        # If the product is not found in the ports section (unlikely but possible)
                        print(f"  Product: {product}, CVE: {cve}, Severity Score: {vuln_details.get('severity_score', 'N/A')}")
        else:
            print("  No vulnerabilities identified.")
        print("-" * 50)  # Separator for readability

def find_port_with_product(ports, product_name):
    """
    Helper function to find the port and product name for a given product in the ports dictionary.
    Returns a tuple of (port, product_name) if found, otherwise None.
    """
    for port, info in ports.items():
        if 'product' in info and info['product'].startswith(product_name):
            return port, info['product']
    return None
