import ipaddress
import argparse

# Converts a CIDR to a list of IPs
def cidr_to_ips(cidr: str) -> list:
    ip_network = ipaddress.ip_network(cidr)
    return [str(ip) for ip in ip_network.hosts()]

# Generates a list of IPs from the arguments passed to the cli
def generate_ip_list(args: argparse.Namespace) -> list:
    ip_list = []
    if args.subnet:
        ip_list = cidr_to_ips(args.subnet)
    elif args.ip:
        ip_list = [args.ip]
    elif args.file:
        with open(args.file, "r") as ip_file:
            ip_list = ip_file.readlines()

    return ip_list

# Chunk a list into n sized chunks
# Returns a list of lists
def chunk_list(lst: list, n: int) -> list:
    return [lst[i:i + n] for i in range(0, len(lst), n)]