from concurrent.futures import ThreadPoolExecutor, as_completed
from nmap import PortScanner
from lib.scanner import AutoScanner
import logging
import signal

class AsyncRunner:
    def __init__(self, threads: int = 100, exploit_enabled: bool = False, key: str = None):
        self.threads = threads
        self.exploit_enabled = exploit_enabled
        self.key = key
        self.futures = []
        self.executor = ThreadPoolExecutor(max_workers=self.threads)

        # Register signal handler
        signal.signal(signal.SIGINT, self.shutdown)
    
    def submit(self, func, *args):
        future = self.executor.submit(func, *args)
        self.futures.append(future)

    def shutdown(self, signum = None, frame = None):
        logging.info("Shutting down...")
        self.executor.shutdown(wait=True, cancel_futures=True)

    def wait(self):
        for future in as_completed(self.futures):
            pass
        self.shutdown()
        
def run_nmap_scan(scanner_args: dict, runner: AsyncRunner) -> str:
    nm = PortScanner()
    nm.scan(hosts=scanner_args["hosts"], arguments=scanner_args["nmap_args"])
    task = {"nmap_output": nm.get_nmap_last_output(), "key": runner.key}
    # This won't work with ProcessPoolExecutor as is because runner is not pickleable
    # Runner is a reference to the AsyncRunner object that is calling this function
    runner.executor.submit(run_cve_lookup, task)
    logging.info(f"Scanned {scanner_args['hosts']}")
    return nm.get_nmap_last_output()

def run_cve_lookup(scanner_args: dict) -> dict:
    logging.info(f"Looking up CVEs")
    scanner = AutoScanner()
    results = scanner.load_nmap_output(scanner_args["nmap_output"], scanner_args["key"])
    # results is a dictionary of the form {ip: {ports: {...}, vulns: {}}}
    for ip in results:
        for port in results[ip]["vulns"]:
            logging.info(f"IP: {ip}, Port: {port}, Vulns: {results[ip]['vulns'][port]}")
    return results

def run_msf_exploit(scanner_args: dict):
    pass