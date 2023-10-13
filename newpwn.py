# Quickpwn is a set of 3 microservices that take automatically find end exploit vulnerabilities in a network.
# 1. scanner.py - Scans a network for hosts and ports using nmap
# 2. cve-lookup - Uses autopwn-suite to find CVEs for service/product
# 3. metasploit - Uses metasploit to exploit the CVEs

# This file is used as the main cli to run the quickpwn suite.

import argparse
from lib.helper import generate_ip_list, chunk_list
from lib.scanner import AutoScanner
from lib.runner import AsyncRunner
from nmap import PortScanner

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="QuickPwn - Automatically find and exploit vulnerabilities in a network.")

    # Key arguments required for all quickpwn commands.
    parser.add_argument("-s", "--subnet", help="Subnet to scan. Ex: 192.168.0.1/24")
    parser.add_argument("-i", "--ip", help="Single IP to scan.")
    parser.add_argument("-f", "--file", help="File containing IPs to scan.")
    parser.add_argument("-m", "--mqtt", help="Whether to use MQTT for communication.", action="store_true")
    parser.add_argument("-t", "--threads", help="Number of threads to use.", default=10)

    # Output arguments
    parser.add_argument("-sO", "--scan-output", help="File to save scan results to.")
    parser.add_argument("-cO", "--cve-output", help="File to save cve output to.")

    # Scan arguments
    parser.add_argument("-n", "--nmap-args", help="Nmap arguments to use.")
    parser.add_argument("-c", "--chunk-size", help="Number of IPs to scan at once.", default=1)
    parser.add_argument("-ss", "--saved-scan", help="Use a saved scan instead of running a new one.")

    # CVE arguments
    parser.add_argument("-k", "--key", help="NIST CVE Database API key.")

    # Exploit arguments
    parser.add_argument("-e", "--exploit", help="Automatically run exploits against IPs.")
    parser.add_argument("-lp", "--linux-payload", help="Linux payload to use.")
    parser.add_argument("-wp", "--windows-payload", help="Windows payload to use.")
    parser.add_argument("-rhost", "--remote-host", help="Remote host to use if no payload.")
    parser.add_argument("-rport", "--remote-port", help="Remote port to use if no payload.")

    args = parser.parse_args()
    if not args.subnet and not args.ip and not args.file:
        parser.error("Must specify subnet, IP, or file to scan.")

    return args

def main():
    args = parse_arguments()

    if not args.mqtt:
        runner = AsyncRunner(threads=args.threads, exploit_enabled=args.exploit)
        if not args.saved_scan:
            targets = generate_ip_list(args)
            for host in chunk_list(targets, args.chunk_size):
                scanner_args = {"hosts": host, "nmap_args": args.nmap_args}
                runner.nmap_queue.put(scanner_args)
            runner.start()
            output = runner.wait_for_output()
        
        scanner = PortScanner()
        if args.saved_scan:
            scanner.analyse_nmap_xml_scan(args.saved_scan)
        else:
            for i
        for host in scanner.all_hosts():
            lookup_args = {"nmap_output": host, "key": args.key}
            runner.cve_queue.put(lookup_args)
        runner.start()

        cve_results = wait_for_cve_results()
        for i in cve_results:
            exploit_args = {"cve_results": i, "linux_payload": args.linux_payload, "windows_payload": args.windows_payload, "remote_host": args.remote_host, "remote_port": args.remote_port}
            run_msf_exploit(exploit_args)


if __name__ == "__main__":
    main()