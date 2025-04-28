from scapy.all import *
from scapy.contrib.ospf import *
import time
import threading
import random

def send_ospf_lsr(neighbor_ip):
    """Kirim paket Link State Request (LSR) ke neighbor"""
    # Header IP unicast ke neighbor router IP
    ip_lsr = IP(src=router_id, dst=str(neighbor_ip))
    
    # Header OSPF tipe 3: Link State Request Packet
    ospf_hdr_lsr = OSPF_Hdr(version=2, type=3, src=router_id2, area=area_id)
    
    # Buat LSR packet dengan parameter yang diberikan
    ospf_lsr_pkt = (
        eth /
        ip_lsr /
        ospf_hdr_lsr /
        OSPF_LSReq(
        ) /
        OSPF_LSReq_Item(
            type=1,
            id="10.10.2.1",
            adrouter="10.10.2.1"
        )
    )
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending LSR packet to {neighbor_ip}")
    sendp(ospf_lsr_pkt, iface=interface, verbose=0)

if __name__ == "__main__":
    send_ospf_lsr('10.10.1.1')