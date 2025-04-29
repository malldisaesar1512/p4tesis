from scapy.all import *
from scapy.contrib.ospf import *
import time
import threading
import random

# Konfigurasi parameter OSPF
router_id = "10.10.1.2"  # Router ID
router_id2 = "192.168.1.1"  # Router ID 2 (Neighbor)
area_id = "0.0.0.0"        # Area ID
interface = "ens5"         # Network interface

# Variabel untuk melacak state neighbor
neighbor_state = "Init"
neighbor_ip = router_id2
dbd_seq_num = random.randint(10000, 50000)
dbd_seq_num_neighbor = None
master = False

# Membuat paket Ethernet
eth = Ether()

# Membuat paket IP dengan destination multicast address OSPF (224.0.0.5)
ip = IP(src=router_id, dst="224.0.0.5")

# Membuat header OSPF (versi 2, tipe 1=Hello)
ospf_header = OSPF_Hdr(version=2, type=1, src=router_id, area=area_id)

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
    sniff(iface=interface, filter="ip proto ospf", prn=lambda x: x.show(), store=0)