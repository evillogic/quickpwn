from concurrent.futures import ThreadPoolExecutor, as_completed
from nmap import PortScanner
from lib.scanner import AutoScanner
import logging
import signal
from pymetasploit3.msfrpc import MsfRpcClient
import docker
from time import sleep
from lib.printers import print_scan_results, print_vuln_details

class AsyncRunner:
    def __init__(self, threads: int = 100, exploit_enabled: bool = False, key: str = None):
        self.threads = threads
        self.exploit_enabled = exploit_enabled
        self.key = key
        self.futures = []
        self.executor = ThreadPoolExecutor(max_workers=self.threads)

        # Register signal handler
        signal.signal(signal.SIGINT, self.shutdown)

        if self.exploit_enabled:
            # Start metasploit container
            self.docker_client = docker.from_env()
            self.metasploit_container = self.docker_client.containers.run(
                "metasploitframework/metasploit-framework:6.3.47",
                detach=True,
                ports={"55553/tcp": 55553, "4444/tcp": 4444},
                tty=True,
                command="./msfconsole -x \"load msgrpc Pass='msf' User='msf' SSL=false ServerHost=0.0.0.0 ServerPort=55553\""
            )
            logging.info("Waiting for metasploit to start...")
            sleep(10)
            #logging.info(f"Metasploit container started: {self.metasploit_container.logs()}")
            # equivalent cli command is `docker run -d -p 55553:55553 metasploitframework/metasploit-framework:6.3.47`
            logging.info(f"Metasploit container started: {self.metasploit_container.id}")
            #output = self.metasploit_container.exec_run("load msgrpc Pass='msf' User='msf' SSL=false ServerHost=metasploit ServerPort=55553")
            #logging.info(f"Metasploit output: {output}")

            # Connect to metasploit
            self.client = MsfRpcClient("msf", server="localhost", port=55553)
            logging.info("Connected to metasploit")
    
    def submit(self, func, *args):
        future = self.executor.submit(func, *args)
        self.futures.append(future)

    def shutdown(self, signum = None, frame = None):
        logging.info("Shutting down...")
        self.executor.shutdown(wait=True, cancel_futures=True)
        if self.exploit_enabled:
            self.metasploit_container.stop()
            self.metasploit_container.remove()
            logging.info("Metasploit container stopped")

    def wait(self):
        for future in as_completed(self.futures):
            pass
        self.shutdown()

def run_nmap_scan(scanner_args: dict, runner: AsyncRunner) -> str:
    nm = PortScanner()
    nm.scan(hosts=scanner_args["hosts"], arguments=scanner_args["nmap_args"])
    print_scan_results(nm)
    task = {"nmap_output": nm.get_nmap_last_output(), "key": runner.key}
    # This won't work with ProcessPoolExecutor as is because runner is not pickleable
    # Runner is a reference to the AsyncRunner object that is calling this function
    runner.executor.submit(run_cve_lookup, task, runner)
    return nm.get_nmap_last_output()
 
def run_cve_lookup(cve_task: dict, runner: AsyncRunner) -> dict:
    logging.info(f"Looking up CVEs")
    scanner = AutoScanner()
    results = scanner.load_nmap_output(cve_task["nmap_output"], cve_task["key"])
    # results is a dictionary of the form {ip: {ports: {...}, vulns: {}}}
    print_vuln_details(results)
    return results

def run_msf_exploit(exploit_task: dict, runner: AsyncRunner):
    logging.info("Running exploit")
    pass