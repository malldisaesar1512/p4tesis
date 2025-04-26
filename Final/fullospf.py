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
    global neighbor_state
    while True:
        if neighbor_state == "Init":
            ospf_hello.neighbors = []
        elif neighbor_state == "2-Way":
            ospf_hello.neighbors = [neighbor_ip]
        sendp(ospf_packet, iface=interface, verbose=0)
        print(f"Sent OSPF Hello packet at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
        time.sleep(interval)

def send_ospf_dbd(neighbor_ip, flags, seq_num):
    """Kirim paket Database Description (DBD) ke neighbor"""
    # Header IP unicast ke neighbor router IP
    ip_dbd = IP(src=router_id, dst=str(neighbor_ip))
    
    # Header OSPF tipe 2: Database Description Packet
    ospf_hdr_dbd = OSPF_Hdr(version=2, type=2, src=router_id, area=area_id)
    
    # Buat DBD packet dengan flag dan sequence number yang diberikan
    ospf_dbd_pkt = (
        eth /
        ip_dbd /
        ospf_hdr_dbd /
        OSPF_DBDesc(
            options=0x02,
            mtu=1500,
            dbdescr=flags,
            ddseq=seq_num
        )
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending DBD packet to {neighbor_ip} - Flags: {flags}, Seq: {seq_num}")
    sendp(ospf_dbd_pkt, iface=interface, verbose=0)

def send_ospf_lsr(neighbor_ip, lsr_type, lsr_id, lsr_adv_router):
    """Kirim paket Link State Request (LSR) ke neighbor"""
    # Header IP unicast ke neighbor router IP
    ip_lsr = IP(src=router_id, dst=str(neighbor_ip))
    
    # Header OSPF tipe 3: Link State Request Packet
    ospf_hdr_lsr = OSPF_Hdr(version=2, type=3, src=router_id, area=area_id)
    
    # Buat LSR packet dengan parameter yang diberikan
    ospf_lsr_pkt = (
        eth /
        ip_lsr /
        ospf_hdr_lsr /
        OSPF_LSReq(
            lsr_type=lsr_type,
            lsr_id=lsr_id,
            lsr_adv_router=lsr_adv_router
        )
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending LSR packet to {neighbor_ip} - Type: {lsr_type}, ID: {lsr_id}, Adv Router: {lsr_adv_router}")
    sendp(ospf_lsr_pkt, iface=interface, verbose=0)

def send_ospf_lsu(neighbor_ip, lsas):
    """Kirim paket Link State Update (LSU) ke neighbor"""
    # Header IP unicast ke neighbor router IP
    ip_lsu = IP(src=router_id, dst=str(neighbor_ip))
    
    # Header OSPF tipe 4: Link State Update Packet
    ospf_hdr_lsu = OSPF_Hdr(version=2, type=4, src=router_id, area=area_id)
    
    # Buat LSU packet dengan LSAs yang diberikan
    ospf_lsu_pkt = (
        eth /
        ip_lsu /
        ospf_hdr_lsu /
        OSPF_LSUpd(
            lsas=lsas
        )
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending LSU packet to {neighbor_ip} - LSAs: {lsas}")
    sendp(ospf_lsu_pkt, iface=interface, verbose=0)

def handle_incoming_packet(packet):
    global neighbor_state, dbd_seq_num, dbd_seq_num_neighbor, master
    
    if not packet.haslayer(OSPF_Hdr):
        return
    
    ospfhdr_layer = packet.getlayer(OSPF_Hdr)
    
    if ospfhdr_layer.type == 1:  # Hello Packet
        # Paket hello diterima -> kirim DBD sebagai respons ke source IP di layer IP
        src_ip_of_neighbor = packet[IP].src
        if neighbor_state == "Init":
            neighbor_state = "2-Way"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received HELLO from {src_ip_of_neighbor}, moving to 2-Way")
            ospf_hello.neighbors = [src_ip_of_neighbor]
            send_ospf_dbd(src_ip_of_neighbor, ["I", "M"], dbd_seq_num)
    
    elif ospfhdr_layer.type == 2:  # DBD Packet
        dbd_layer = packet.getlayer(OSPF_DBDesc)
        src_ip_of_neighbor = packet[IP].src
        
        if neighbor_state == "2-Way":
            if "I" in dbd_layer.dbdescr:
                if "MS" in dbd_layer.dbdescr:
                    master = True
                    neighbor_state = "ExStart"
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received DBD from {src_ip_of_neighbor}, moving to ExStart (Master)")
                    dbd_seq_num_neighbor = dbd_layer.ddseq
                    send_ospf_dbd(src_ip_of_neighbor, ["MS"], dbd_seq_num)
                else:
                    master = False
                    neighbor_state = "ExStart"
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received DBD from {src_ip_of_neighbor}, moving to ExStart (Slave)")
                    dbd_seq_num_neighbor = dbd_layer.ddseq
                    send_ospf_dbd(src_ip_of_neighbor, ["MS"], dbd_seq_num)
        
        elif neighbor_state == "ExStart":
            if "MS" in dbd_layer.dbdescr:
                if master:
                    if dbd_layer.ddseq == dbd_seq_num:
                        neighbor_state = "Exchange"
                        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received DBD from {src_ip_of_neighbor}, moving to Exchange (Master)")
                        send_ospf_dbd(src_ip_of_neighbor, ["M"], dbd_seq_num)
                else:
                    if dbd_layer.ddseq == dbd_seq_num_neighbor:
                        neighbor_state = "Exchange"
                        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received DBD from {src_ip_of_neighbor}, moving to Exchange (Slave)")
                        send_ospf_dbd(src_ip_of_neighbor, ["M"], dbd_seq_num)
        
        elif neighbor_state == "Exchange":
            if "M" in dbd_layer.dbdescr:
                neighbor_state = "Loading"
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received DBD from {src_ip_of_neighbor}, moving to Loading")
                send_ospf_lsr(src_ip_of_neighbor, 1, "192.168.1.1", "192.168.1.1")
    
    elif ospfhdr_layer.type == 3:  # LSR Packet
        lsr_layer = packet.getlayer(OSPF_LSReq)
        src_ip_of_neighbor = packet[IP].src
        
        if neighbor_state == "Loading":
            lsas = [
                OSPF_LSA_Hdr(
                    age=360,
                    options=0x02,
                    type=1,  # Router LSA
                    id="192.168.1.1",
                    adrouter="192.168.1.1",
                    seq=0x80000123  # Sequence number
                ),
                OSPF_LSA_Hdr(
                    age=360,
                    options=0x02,
                    type=2,  # Network LSA
                    id="192.168.1.0",
                    adrouter="192.168.1.1",
                    seq=0x80000124  # Sequence number
                )
            ]
            send_ospf_lsu(src_ip_of_neighbor, lsas)
            neighbor_state = "Full"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received LSR from {src_ip_of_neighbor}, moving to Full")
    
    elif ospfhdr_layer.type == 4:  # LSU Packet
        src_ip_of_neighbor = packet[IP].src
        
        if neighbor_state == "Loading":
            neighbor_state = "Full"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received LSU from {src_ip_of_neighbor}, moving to Full")

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
            time.sleep(1)
    except KeyboardInterrupt:
        print("Program terminated by user.")
