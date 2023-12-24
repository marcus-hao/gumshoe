#!/usr/bin/env python3
import argparse
from scapy.all import *

results = ""    # Global variable to store results

def syn_scan(target_ip, target_ports):
    for port in target_ports:
        # Create the TCP SYN packet with destination port
        syn_packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags="S")

        # Send the packet and wait for a response
        response = sr1(syn_packet, timeout=1, verbose=0)

        # Check if a response was received
        if response:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                print(f"Port {port} is open")
            else:
                print(f"Port {port} is closed")
        else:
            print(f"Port {port} is filtered or unreachable")

def udp_scan(target_ip, target_ports):
    for port in target_ports:
        # Create the UDP packet with destination port
        udp_packet = IP(dst=target_ip) / UDP(dport=port)
        
        # Send the packet and wait for a response
        response = sr1(udp_packet, timeout=1, verbose=0)

        # Check if a response was receieved
        if response:
            if response.haslayer(UDP):
                print(f"Port {port} is open")
            else:
                print(f"Port {port} is filtered or unreachable")
        else:
            print(f"Port {port} is closed")

def fin_scan(target_ip, target_ports):
    for port in target_ports:
        # Create the TCP FIN packet with destination port
        fin_packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags="F")

        # Send the packet and wait for a response
        response = sr1(fin_packet, timeout=1, verbose=0)

        # Check for response
        if response:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x04:
                print(f"Port {port} is closed")
            else:
                print(f"Port {port} is filtered/opened")
        else:
            print(f"Port {port} is filtered/opened")        

def xmas_scan(target_ip, target_ports):
    for port in target_ports:
        # Create the Xmas packet with destination port by setting PUSH, URG, FIN flags
        xmas_packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags="PFU")

        # Send the packet and wait for a response
        response = sr1(xmas_packet, timeout=1, verbose=0)

        # Check for response
        if response:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x04:
                print(f"Port {port} is closed")
            else:
                print(f"Port {port} is filtered/opened")
        else:
            print(f"Port {port} is filtered/opened")        

def null_scan(target_ip, target_ports):
    for port in target_ports:
        # Create the TCP NULL packet with destination port by not setting any flags
        null_packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags="")

        # Send the packet and wait for a response
        response = sr1(null_packet, timeout=1, verbose=0)

        # Check for response
        if response:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x04:
                print(f"Port {port} is closed")
            else:
                print(f"Port {port} is filtered/opened")
        else:
            print(f"Port {port} is filtered/opened")        

def ping_sweep(target_network):
    # Create the ICMP echo request with target network
    icmp_packet = IP(dst=target_network) / ICMP()

    # Send the packet and receieve responses
    responses, _ = sr(icmp_packet, timeout=1, verbose=0)

    for response in responses:
        # Extract the host IP from the response
        host_ip = response[0][IP].src
        print(f"Host {host_ip} is reachable")

def os_fingerprint():
    return

def output_to_file(results, filepath):
    try:
        with open(filepath, "w") as file:
            file.write(results)
    except IOError as e:
        print(f"Error writing to file: {e}")

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

if __name__ == "__main__":
    print("""
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
                                                                                                 

""")
    
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
    parser.add_argument("-o", "--output", action="store_true", help="Output the results to a text file")
    parser.add_argument("-os", "--os", action="store_true", help="Fingerprint the operating system")
    # Positional arguments
    parser.add_argument("ip_address", help="Target IP address")

    args = parser.parse_args()

    target_ip = args.ip_address
    target_ports = args.port

    if args.syn:
        syn_scan(target_ip, target_ports)
    elif args.version:
        print("We'll do something about this later...")
    elif args.udp:
        udp_scan(target_ip, target_ports)
    elif args.fin:
        fin_scan(target_ip, target_ports)
    elif args.null:
        null_scan(target_ip, target_ports)
    elif args.xmas:
        xmas_scan(target_ip, target_ports)
    elif args.ping:
        ping_sweep(target_ip)
    else:
        print("No scan options selected?!")

    if args.output:
        output_to_file(results, args.output)

    print("Scan completed")