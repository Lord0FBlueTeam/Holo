import nmap
import argparse
import time
import os

class HoloScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(self, target, options):
        print(f'Holo is scanning: {target} {options}')
        start_time = time.time()

        try:
            # Check if -T4 is not already in options
            if '-T4' not in options:
                options = '-T4 ' + options  # Add -T4

            self.nm.scan(arguments=f"{options} {target}")

            for host in self.nm.all_hosts():
                if host != '127.0.0.1':
                    os_info = self.get_os_info(self.nm[host])
                    print(f'Host: {host} ({os_info})')

                    for proto in self.nm[host].all_protocols():
                        lport = self.nm[host][proto].keys()

                        for port in lport:
                            state = self.nm[host][proto][port]['state']
                            service = self.nm[host][proto][port]['name']
                            version = self.nm[host][proto][port]['version']

                            print(f'Port {port}/{proto} {state} ({service})')

                            if version:
                                print(f'Version: {version}')

        except nmap.PortScannerError as e:
            print(f'Holo error: Unable to scan. Please check your input. Error: {e}')

        except Exception as e:
            print(f'An unexpected error occurred: {e}')

        end_time = time.time()
        print(f'Scan completed in {end_time - start_time} seconds')

    def get_os_info(self, host_info):
        os_info = host_info.get('osfinger', '')
        return os_info

def main():
    parser = argparse.ArgumentParser(description='Holo Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('options', nargs='*', help='Additional nmap options')

    args = parser.parse_args()
    target = args.target
    options = ' '.join(args.options)  # Include all provided options

    scanner = HoloScanner()
    scanner.scan(target, options)

if __name__ == '__main__':
    main()
