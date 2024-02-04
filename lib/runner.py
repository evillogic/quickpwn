from concurrent.futures import ProcessPoolExecutor, as_completed
from nmap import PortScanner
from lib.scanner import AutoScanner
import logging

class AsyncRunner:
    def __init__(self, threads: int = 10, exploit_enabled: bool = False, key: str = None):
        self.threads = threads
        self.exploit_enabled = exploit_enabled
        self.key = key
        self.futures = []
        self.executor = ProcessPoolExecutor(max_workers=self.threads)
    
    def submit(self, func, *args):
        future = self.executor.submit(func, *args)
        if func == run_nmap_scan:
            future.add_done_callback(self.nmap_callback)
        self.futures.append(future)

    def shutdown(self):
        logging.info("Shutting down...")
        self.executor.shutdown(wait=True, cancel_futures=True)

    def wait(self):
        for future in as_completed(self.futures):
            logging.info(future.result())
        self.shutdown()

    def nmap_callback(self, future):
        result = future.result()
        # TODO: Print some info about the result
        logging.info("Nmap scan complete.")
        task = {"nmap_output": result, "key": self.key}
        self.submit(run_cve_lookup, task)
        
def run_nmap_scan(scanner_args: dict) -> str:
    nm = PortScanner()
    nm.scan(hosts=scanner_args["hosts"], arguments=scanner_args["nmap_args"])

    return nm.get_nmap_last_output()

def run_cve_lookup(scanner_args: dict) -> dict:
    scanner = AutoScanner()
    results = scanner.load_nmap_output(scanner_args["nmap_output"], scanner_args["key"])
    return results

def run_msf_exploit(scanner_args: dict):
    pass