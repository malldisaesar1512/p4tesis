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

# State machine variables
state = "Init"
neighbor_state = "Init"
neighbor_ip = router_id2
dbd_seq = random.randint(10000, 50000)
neighbor_dbd_seq = None
lsdb = []

# Membuat paket Ethernet
eth = Ether()

# Membuat paket IP dengan destination multicast address OSPF (224.0.0.5)
ip = IP(src=router_id, dst="224.0.0.5")

# Membuat header OSPF (versi 2, tipe 1=Hello)
ospf_header = OSPF_Hdr(version=2, type=1, src=router_id, area=area_id)

# Membuat paket OSPF Hello dengan parameter standar
ospf_hello = OSPF_Hello(
    mask="255.255.255.0",
    hellointerval=10,
    options=0x02,
    prio=128,
    deadinterval=40,
    router=router_id,
    backup="0.0.0.0",
    neighbors=[]
)

# Menggabungkan semua layer menjadi satu paket lengkap
ospf_packet = eth / ip / ospf_header / ospf_hello

# Fungsi untuk mengirim paket OSPF Hello setiap 10 detik
def send_ospf_hello_periodically(interval):
    while True:
        sendp(ospf_packet, iface=interface, verbose=0)
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sent OSPF Hello packet")
        time.sleep(interval)

def send_ospf_dbd(neighbor_ip):
    """Kirim paket Database Description (DBD) ke neighbor"""
    # Header IP unicast ke neighbor router IP
    ip_dbd = IP(src=router_id, dst=str(neighbor_ip))
    
    # Header OSPF tipe 2: Database Description Packet
    ospf_hdr_dbd = OSPF_Hdr(version=2, type=2, src=router_id, area=area_id)
    
    # Buat DBD packet dengan flag Init bit set (bit kedua), seq number awal misal 1.
    ospf_dbd_pkt = (
        eth /
        ip_dbd /
        ospf_hdr_dbd /
        OSPF_DBDesc(
            options=0x02,
            mtu=1500,
            dbdescr=["I", "M", "MS"],  # 'I' berarti Init bit set
            ddseq=dbd_seq
        )
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending DBD packet to {neighbor_ip}")
    sendp(ospf_dbd_pkt, iface=interface, verbose=0)

def send_ospf_dbd_ack(neighbor_ip, seqnum):
    """Kirim paket Database Description (DBD) ACK ke neighbor"""
    # Header IP unicast ke neighbor router IP
    ip_dbd = IP(src=router_id, dst=str(neighbor_ip))
    
    # Header OSPF tipe 2: Database Description Packet
    ospf_hdr_dbd = OSPF_Hdr(version=2, type=2, src=router_id, area=area_id)
    
    # Buat DBD packet dengan flag More bit set (bit ketiga), seq number awal misal 1.
    ospf_dbd_pkt = (
        eth /
        ip_dbd /
        ospf_hdr_dbd /
        OSPF_DBDesc(
            options=0x02,
            mtu=1500,
            dbdescr=["M"],  # 'M' berarti More bit set
            ddseq=seqnum
        )
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending DBD ACK packet to {neighbor_ip}")
    sendp(ospf_dbd_pkt, iface=interface, verbose=0)

def send_ospf_lsu(neighbor_ip):
    """Kirim paket Link State Update (LSU) ke neighbor"""
    # Header IP unicast ke neighbor router IP
    ip_lsu = IP(src=router_id, dst=str(neighbor_ip))
    
    # Header OSPF tipe 4: Link State Update Packet
    ospf_hdr_lsu = OSPF_Hdr(version=2, type=4, src=router_id, area=area_id)
    
    # Buat LSU packet dengan LSA headers
    ospf_lsu_pkt = (
        eth /
        ip_lsu /
        ospf_hdr_lsu /
        OSPF_LSU(
            lsalist=[
                OSPF_LSA_Hdr(
                    age=360,
                    options=0x02,
                    type=1,  # Router LSA
                    id=router_id,
                    adrouter=router_id,
                    seq=0x80000123  # Sequence number
                ),
                OSPF_LSA_Hdr(
                    age=360,
                    options=0x02,
                    type=2,  # Network LSA
                    id="192.168.1.0",
                    adrouter=router_id,
                    seq=0x80000124  # Sequence number
                )
            ]
        )
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending LSU packet to {neighbor_ip}")
    sendp(ospf_lsu_pkt, iface=interface, verbose=0)

def handle_incoming_packet(packet):
    global state, neighbor_state, neighbor_dbd_seq, lsdb
    
    if not packet.haslayer(OSPF_Hdr):
        return
    
    ospfhdr_layer = packet.getlayer(OSPF_Hdr)
    
    if ospfhdr_layer.type == 1:  # Hello Packet
        # Paket hello diterima -> kirim DBD sebagai respons ke source IP di layer IP
        src_ip_of_neighbor = packet[IP].src
        if src_ip_of_neighbor == neighbor_ip:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received HELLO from {src_ip_of_neighbor}, sending DBD...")
            state = "ExStart"
            send_ospf_dbd(src_ip_of_neighbor)
    
    elif ospfhdr_layer.type == 2:  # DBD Packet
        dbd_layer = packet.getlayer(OSPF_DBDesc)
        src_ip_of_neighbor = packet[IP].src
        if src_ip_of_neighbor == neighbor_ip:
            if state == "ExStart":
                neighbor_dbd_seq = dbd_layer.ddseq
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received DBD from {src_ip_of_neighbor}, sending DBD ACK...")
                state = "Exchange"
                send_ospf_dbd_ack(src_ip_of_neighbor, neighbor_dbd_seq)
            elif state == "Exchange":
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received DBD ACK from {src_ip_of_neighbor}, sending LSU...")
                state = "Loading"
                send_ospf_lsu(src_ip_of_neighbor)
    
    elif ospfhdr_layer.type == 4:  # LSU Packet
        src_ip_of_neighbor = packet[IP].src
        if src_ip_of_neighbor == neighbor_ip:
            if state == "Loading":
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received LSU from {src_ip_of_neighbor}, transitioning to Full...")
                state = "Full"
                # Simpan LSA dari LSU ke LSDB
                lsu_layer = packet.getlayer(OSPF_LSU)
                for lsa in lsu_layer.lsalist:
                    lsdb.append(lsa)
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] LSDB: {lsdb}")

def sniff_packets():
    sniff(iface=interface, filter="ip proto ospf", prn=lambda pkt: handle_incoming_packet(pkt), store=False)

if __name__ == "__main__":
    hello_thread = threading.Thread(target=lambda: send_ospf_hello_periodically(10))
    hello_thread.daemon = True
    hello_thread.start()
    
    recv_thread = threading.Thread(target=lambda: sniff_packets())
    recv_thread.daemon = True
    recv_thread.start()
    
    try:
        while True:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Current State: {state}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("Program terminated by user.")
