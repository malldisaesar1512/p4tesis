from scapy.all import *
from scapy.contrib.ospf import *
import sys

def handle_ospf_packet(packet):
    if OSPF_Hdr in packet:
        print(f"Received OSPF packet type: {packet[OSPF_Hdr].type}")
        
        # Handle different OSPF packet types
        if packet[OSPF_Hdr].type == 1:  # Hello
            print("Received OSPF Hello packet")
            # Create and send Hello response
            response = create_ospf_hello()
            send(response)
            
        elif packet[OSPF_Hdr].type == 2:  # Database Description
            print("Received Database Description packet")
            
        elif packet[OSPF_Hdr].type == 3:  # Link State Request
            print("Received Link State Request packet")
            
        elif packet[OSPF_Hdr].type == 4:  # Link State Update
            print("Received Link State Update packet")
            
        elif packet[OSPF_Hdr].type == 5:  # Link State Acknowledgment
            print("Received Link State Acknowledgment packet")

def create_ospf_hello():
    # Create basic OSPF Hello packet
    eth = Ether()
    ip = IP(dst="224.0.0.5")  # OSPF All Routers multicast address
    ospf_hdr = OSPF_Hdr(type=1)  # Type 1 is Hello
    ospf_hello = OSPF_Hello(
        router_id="1.1.1.1",
        area_id="0.0.0.0",
        auth_type=0
    )
    return eth/ip/ospf_hdr/ospf_hello

def start_ospf_listener():
    try:
        print("Starting OSPF packet listener...")
        # Filter for OSPF packets (protocol 89)
        sniff(filter="ip proto 89", prn=handle_ospf_packet, store=0)
    except KeyboardInterrupt:
        print("\nStopping OSPF listener...")
        sys.exit(0)

if __name__ == "__main__":
    start_ospf_listener()