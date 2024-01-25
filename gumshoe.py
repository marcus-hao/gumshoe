#!/usr/bin/env python3
import argparse
from datetime import datetime
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import socket

def syn_scan(ip, port):
    # Set SYN flag in TCP header
    syn_packet = IP(dst=ip) / TCP(sport=RandShort(), dport=port, flags="S")
    response = sr1(syn_packet, timeout=1, verbose=0)

    if response:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            return True
        else:
            return False
    return False

def udp_scan(ip, port):
    # Create the UDP packet with destination port
    udp_packet = IP(dst=ip) / UDP(dport=port)
    
    # Send the packet and wait for a response
    response = sr1(udp_packet, timeout=1, verbose=0)

    # Check if a response was receieved
    if response:
        if response.haslayer(UDP):
            return True
        else:
            return False
    return False

def fin_scan(ip, port):
    # Set FIN flag in TCP header
    fin_packet = IP(dst=ip) / TCP(sport=RandShort(), dport=port, flags="F")
    response = sr1(fin_packet, timeout=1, verbose=0)
    if response:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x04:
            return False
        else:
            return True
    return True

def xmas_scan(ip, port):
    # Set PUSH, URG, FIN flags in TCP header
    xmas_packet = IP(dst=ip) / TCP(sport=RandShort(), dport=port, flags="PFU")
    response = sr1(xmas_packet, timeout=1, verbose=0)
    if response:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x04:
            return False
        else:
            return True
    return True

def null_scan(ip, port):
    # Don't set any flags in the TCP header
    null_packet = IP(dst=ip) / TCP(sport=RandShort(), dport=port, flags="")
    response = sr1(xmas_packet, timeout=1, verbose=0)
    if response:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x04:
            return False
        else:
            return True
    return True

def ping_sweep(ip):
    # Create the ICMP echo request with target network
    icmp_packet = IP(dst=ip) / ICMP()

    # Send the packet and receieve responses
    responses, _ = sr(icmp_packet, timeout=1, verbose=0)

    results = ""
    for response in responses:
        # Extract host ip from the respones
        host_ip = response[0][IP].src
        results += f"Host {host_ip} is UP\n"

    return results

def get_banner(ip, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip, port))
        s.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode("utf-8") + b'\r\n\r\n')
        return s.recv(1024)
    except:
        return None

def parse_ports(ports):
    try:
        # Handle port ranges or split input by commas
        port_list = []
        for part in ports.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                port_list.extend(range(start, end+1))
            else:
                port_list.append(int(part))

        # Validate the list of ports
        if all(0 < port <= 65535 for port in port_list):
            return port_list
        else:
            raise argparse.ArgumentTypeError("Invalid port number")
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid port specification")

def output_to_file(results, filepath):
    try:
        with open(filepath, "w") as f:
            f.write(results)
    except IOError as e:
        print(f"Error writing to file: {e}")

# Parse arguments
parser = argparse.ArgumentParser()
# Scan options
parser.add_argument("-sS", "--syn", action="store_true", help="Perform a SYN scan")
parser.add_argument("-sV", "--version", action="store_true", help="Probe to determine service information")
parser.add_argument("-sU", "--udp", action="store_true", help="Perform a UDP scan")
parser.add_argument("-sF", "--fin", action="store_true", help="Perform a FIN scan")
parser.add_argument("-sN", "--null", action="store_true", help="Perform a null scan")
parser.add_argument("-sX", "--xmas", action="store_true", help="Perform an Xmas scan")
parser.add_argument("-P", "--ping", action="store_true", help="Perform a ping sweep")
parser.add_argument("-p", "--port", type=parse_ports, help="Specify port range or list to scan (e.g., 1-1023, 80, 443)")
parser.add_argument("-o", "--output", help="Output the results to a text file")
parser.add_argument("-os", "--os", action="store_true", help="Fingerprint the operating system")
# Positional arguments
parser.add_argument("ip_address", help="Target IP address")

args = parser.parse_args()

target_ip = args.ip_address
target_ports = args.port if args.port else list(range(1,1024))

start_time = datetime.now()

output = ""

logo = """
         _        _                  _   _         _            _       _    _            _      
        /\ \     /\_\               /\_\/\_\ _    / /\         / /\    / /\ /\ \         /\ \    
       /  \ \   / / /         _    / / / / //\_\ / /  \       / / /   / / //  \ \       /  \ \   
      / /\ \_\  \ \ \__      /\_\ /\ \/ \ \/ / // / /\ \__   / /_/   / / // /\ \ \     / /\ \ \  
     / / /\/_/   \ \___\    / / //  \____\__/ // / /\ \___\ / /\ \__/ / // / /\ \ \   / / /\ \_\ 
    / / / ______  \__  /   / / // /\/________/ \ \ \ \/___// /\ \___\/ // / /  \ \_\ / /_/_ \/_/ 
   / / / /\_____\ / / /   / / // / /\/_// / /   \ \ \     / / /\/___/ // / /   / / // /____/\    
  / / /  \/____ // / /   / / // / /    / / /_    \ \ \   / / /   / / // / /   / / // /\____\/    
 / / /_____/ / // / /___/ / // / /    / / //_/\__/ / /  / / /   / / // / /___/ / // / /______    
/ / /______\/ // / /____\/ / \/_/    / / / \ \/___/ /  / / /   / / // / /____\/ // / /_______\   
\/___________/ \/_________/          \/_/   \_____\/   \/_/    \/_/ \/_________/ \/__________/   
                                                                                                 

"""

menu = logo + f"\nStarting Gumshoe v1.0 at {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n" + f"Gumshoe scan report for {target_ip}\n"

if not args.output:
    print(menu)
else:
    output += menu

# Parse scanning options
if args.ping:
    output += ping_sweep(target_ip)
else:
    for port in target_ports:
        if args.syn and args.version:
            status = syn_scan(target_ip, port)
            if status:
                banner = get_banner(target_ip, port)
                if banner:
                    output += f"Port {port}: OPEN - {banner}\n"
                else:
                    continue
            else:
                continue
        elif args.syn:
            status = syn_scan(target_ip, port)
            if status:
                output += f"Port {port}: OPEN\n"
            else:
                continue
        elif args.udp:
            status = udp_scan(target_ip, port)
            if status:
                output += f"Port {port}: OPEN\n"
            else:
                continue
        elif args.fin:
            status = fin_scan(target_ip, port)
            if status:
                output += f"Port {port}: OPEN\n"
            else:
                continue
        elif args.xmas:
            status = xmas_scan(target_ip, port)
            if status:
                output += f"Port {port}: OPEN\n"
            else:
                continue
        elif args.null:
            status = null_scan(target_ip, port)
            if status:
                output += f"Port {port}: OPEN\n"
            else:
                continue

end_time = datetime.now()
elapsed_time = end_time - start_time
output += f"Gumshoe scan completed in {elapsed_time.total_seconds()} seconds.\n"

if args.output:
    output_to_file(output, args.output)
else:
    print(output)