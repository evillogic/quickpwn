import ipaddress
import argparse
import logging

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

# Straight off StackOverflow
class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def configure_logging():
    # Configure the root logger
    # Not sure why this needs to be done, but it does
    logging.basicConfig(level=logging.DEBUG)

    # Get the root logger
    logger = logging.getLogger()

    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Create console handler with debug level
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    # Create and set the custom formatter
    ch.setFormatter(CustomFormatter())

    # Add the console handler to the root logger
    logger.addHandler(ch)