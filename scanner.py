import socket
import threading
import sys
import argparse

class Scanner:
    def __init__(self, ip, start_port, end_port):
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port
        self.threads = []

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown"
                print(f"Port {port} is open. Service: {service}", flush=True)
            sock.close()
        except socket.error:
            pass

    def scan_range(self):
        for port in range(self.start_port, self.end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            thread.start()
            self.threads.append(thread)

        for thread in self.threads:
            thread.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Port scanner")
    parser.add_argument("target" , help="The target IP address to scan")
    parser.add_argument("-p", "--port", help="The port range to scan. E.g. '0-1024'", default="0-1024", nargs="?")

    args = parser.parse_args()

    if args.target is None:
        if len(sys.argv) >= 1:
            ip_address = sys.argv[1]
        else:
            sys.exit("You must provide an IP address to scan.")
    else:
        ip_address = args.target
    
    port_range = args.port.split("-")
    start_port = int(port_range[0])
    end_port = int(port_range[1])

    if start_port < 0 or start_port > 65535 or end_port < 0 or end_port > 65535:
        sys.exit("Invalid port range. Ports must be between 0 and 65535.")


    scanner = Scanner(ip_address, start_port, end_port)

    scanner.scan_range()
