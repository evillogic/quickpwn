import queue
import threading
from concurrent.futures import ProcessPoolExecutor
from nmap import PortScanner
from quickpwn.lib.scanner import AutoScanner

class AsyncRunner:
    def __init__(self, threads: int = 10, exploit_enabled: bool = False):
        self.nmap_queue = queue.Queue()
        self.cve_queue = queue.Queue()
        self.exploit_queue = queue.Queue()
        self.threads = threads
        self.exploit_enabled = exploit_enabled

        # Start runner on a new thread.
        runner_thread = threading.Thread(target=self.runner)
        runner_thread.start()

    def runner(self):
        with ProcessPoolExecutor(max_workers=self.threads) as executor:
            should_continue = True
            while should_continue:
                if not self.nmap_queue.empty():
                    executor.submit(self.nmap_queue.get())

                if not self.cve_queue.empty():
                    executor.submit(self.cve_queue.get())

                if not self.exploit_queue.empty():
                    executor.submit(self.exploit_queue.get())

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