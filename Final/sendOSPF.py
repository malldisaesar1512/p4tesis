from os import link
from socket import timeout
from scapy.all import *
from scapy.contrib.ospf import *
import time
import threading
import random

# Konfigurasi parameter OSPF
router_id = "10.10.1.2"  # Router ID
router_id2 = "192.168.1.1" # Router ID 2
area_id = "0.0.0.0"        # Area ID
interface = "ens5"         # Network interface
neighbor_state = "Down"
neighbor_ip = "10.10.1.1"
dbd_seq_num = random.randint(10000, 50000)
dbd_seq_num_neighbor = None
master = False
ipbroadcast = "224.0.0.5"

# Membuat paket Ethernet
eth = Ether()

# Membuat paket IP dengan destination multicast address OSPF (224.0.0.5)
ip = IP(src=router_id, dst="224.0.0.5")

# Membuat header OSPF (versi 2, tipe 1=Hello)
ospf_header = OSPF_Hdr(version=2, type=1, src=router_id2, area=area_id)

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

ospf_hello2 = OSPF_Hello(
    mask="255.255.255.0",
    hellointerval=10,
    options=0x02,
    prio=128,
    deadinterval=40,
    router=router_id,
    backup="0.0.0.0",
    neighbors=[neighbor_ip]
)

ospf_hellofull = OSPF_Hello(
    mask="255.255.255.0",
    hellointerval=10,
    options=0x02,
    prio=128,
    deadinterval=40,
    router=router_id2,
    backup=neighbor_ip,
    neighbors=[neighbor_ip]
)

# Menggabungkan semua layer menjadi satu paket lengkap
ospf_packet = eth / ip / ospf_header / ospf_hello
ospf_packet2 = eth / ip / ospf_header / ospf_hello2


# Fungsi untuk mengirim paket OSPF Hello setiap 10 detik
def send_ospf_hello_periodically(interval):
    global neighbor_state
    while True:
        if neighbor_state == "Down":
            # sniff_packets(interval)
            ospf_hello.neighbors = []
            sendp(ospf_packet2, iface=interface, verbose=0)
        elif neighbor_state == "Full":
            # sniff_packets()
            # ospf_hello.neighbors = [neighbor_ip]
            # sendp(ospf_packet3, iface=interface, verbose=0)
            print(f"Sent OSPF Hello packet at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
        time.sleep(interval)
    # while i==0:
    #     sendp(ospf_packet, iface=interface, verbose=1)
    #     print(f"Sent OSPF Hello packet at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    #     i = i + 1
    #     time.sleep(interval)

def send_ospf_2way():
    sendp(ospf_packet, iface=interface, verbose=1)
    print(f"Sent OSPF Hello packet at {time.strftime('%Y-%m-%d %H:%M:%S')}")

def send_ospf_dbd_first(neighbor_ip, flags, seq_num):
    """Kirim paket Database Description (DBD) pertama ke neighbor dengan flags dan seq_num yang benar"""
    ip_dbd = IP(src=router_id, dst=str(neighbor_ip))
    ospf_hdr_dbd = OSPF_Hdr(version=2, type=2, src=router_id2, area=area_id)
    
    # Konversi list flags string ke bitmask integer
    flag_value = 0
    if "I" in flags:
        flag_value |= 0x04  # Init bit
    if "M" in flags:
        flag_value |= 0x02  # More bit
    if "MS" in flags:
        flag_value |= 0x01  # Master/Slave bit
    
    ospf_dbd_pkt1 = (
        eth /
        ip_dbd /
        ospf_hdr_dbd /
        OSPF_DBDesc(
            options=0x02,
            mtu=1500,
            dbdescr=0x07,
            ddseq=seq_num
        )
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending DBD FIRST packet to {neighbor_ip} - Flags: {flags} ({flag_value}), Seq: {seq_num}")
    sendp(ospf_dbd_pkt1, iface=interface, verbose=0)


def send_ospf_dbd(neighbor_router_ip):
    """Kirim paket Database Description (DBD) lanjutan ke neighbor dengan flags dan seq_num yang benar"""
    ip_dbd = IP(src=router_id, dst=str(neighbor_router_ip))
    ospf_hdr_dbd = OSPF_Hdr(version=2, type=2, src=router_id2, area=area_id)
    
    # Flags More + Master/Slave (tanpa Init)
    flag_value = 0x01  #MS
    
    # Pastikan dbd_seq_num_neighbor sudah terisi dan bertambah 1
    seq_num = dbd_seq_num_neighbor + 1 if dbd_seq_num_neighbor is not None else dbd_seq_num + 1
    
    ospf_dbd_pkt2 = (
        eth /
        ip_dbd /
        ospf_hdr_dbd /
        OSPF_DBDesc(
            options=0x02,
            mtu=1500,
            dbdescr=flag_value,
            ddseq=seq_num
        ) /
        OSPF_LSA_Hdr(
            age=360,
            options=0x02,
            type=1,
            id=router_id,
            adrouter=router_id,
            seq=0x80000123
        ) /
        OSPF_LSA_Hdr(
            age=360,
            options=0x02,
            type=1,
            id=router_id2,
            adrouter=router_id2,
            seq=0x80000124
        ) 
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending DBD packet to {neighbor_router_ip} - Flags: M+MS ({flag_value}), Seq: {seq_num}")
    sendp(ospf_dbd_pkt2, iface=interface, verbose=True)

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
        OSPF_LSReq() /
        OSPF_LSReq_Item(type=1, id="10.10.2.1", adrouter="10.10.2.1")/
        OSPF_LSReq_Item(type=1, id="192.168.2.1", adrouter="192.168.2.1")
    )
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending LSR packet to {neighbor_ip}")
    sendp(ospf_lsr_pkt, iface=interface, verbose=0)

def send_ospf_lsu(neighbor_ip):
    """Kirim paket Link State Update (LSU) ke neighbor"""
    # Header IP unicast ke neighbor router IP
    ip_lsu = IP(src=router_id, dst=str(neighbor_ip))
    
    # Header OSPF tipe 4: Link State Update Packet
    ospf_hdr_lsu = OSPF_Hdr(version=2, type=4, src=router_id2, area=area_id)
    
    # Buat LSU packet dengan LSAs yang diberikan
    ospf_lsu_pkt = (
        eth /
        ip_lsu /
        ospf_hdr_lsu /
        OSPF_LSUpd(
            lsacount=2,
            lsalist=[OSPF_Router_LSA(
            age=360,
            options=0x02,
            type=1,  # Router LSA
            id="10.10.1.2",
            adrouter="10.10.1.2",
            seq=0x80000123,  # Sequence number
            linkcount=2,
            linklist=[
                OSPF_Link(
                    id="10.10.1.0",
                    data="10.10.1.0",
                    type=3,
                    metric=1
                ),
                OSPF_Link(
                    id="192.168.1.0",
                    data="192.168.1.0",
                    type=3,
                    metric=1
                )
            ]
        ),
        OSPF_Router_LSA(
            age=360,
            options=0x02,
            type=1,  # router LSA
            id="192.168.1.1",
            adrouter="192.168.1.1",
            seq=0x80000124,  # Sequence number
            linkcount=2,
            linklist=[
                OSPF_Link(
                    id="10.10.1.0",
                    data="10.10.1.0",
                    type=3,
                    metric=1
                ),
                OSPF_Link(
                    id="192.168.1.0",
                    data="192.168.1.0",
                    type=3,
                    metric=1
                )
            ]
        )]
        )  
        
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending LSU packet to {neighbor_ip}")
    sendp(ospf_lsu_pkt, iface=interface, verbose=0)

def send_ospf_lsaack(broadcastip):
    ip_lsack = IP(src=router_id, dst=str(broadcastip))
    
    # Header OSPF tipe 5: Link State ACK Packet
    ospf_hdr_lsack = OSPF_Hdr(version=2, type=5, src=router_id2, area=area_id)
    
    # Buat LSU packet dengan LSAs yang diberikan
    ospf_lsack_pkt = (
        eth /
        ip_lsack /
        ospf_hdr_lsack /
                OSPF_LSAck(
                    lsaheaders=[
                    OSPF_LSA_Hdr(
                    age=360,
                    options=0x02,
                    type=1,
                    id=router_id,
                    adrouter=router_id,
                    seq=0x80000123
                ),
                OSPF_LSA_Hdr(
                    age=360,
                    options=0x02,
                    type=1,
                    id=router_id2,
                    adrouter=router_id2,
                    seq=0x80000124
                )
            ]
        )
    )
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending LS_ACK packet to {broadcastip}")
    sendp(ospf_lsack_pkt, iface=interface, verbose=0)

def handle_incoming_packet(packet):
   global neighbor_state, neighbor_ip, dbd_seq_num, dbd_seq_num_neighbor, master, lsu_id, lsu_adrouter, lsu_seq

   if not packet.haslayer(OSPF_Hdr):
       return
   
   ospfhdr_layer = packet.getlayer(OSPF_Hdr)
#    ospfhdr_layer2 = packet.getlayer(OSPF_Hello)
   checksum = ospfhdr_layer.chksum

   if ospfhdr_layer.type == 1:
         # Hello Packet
       # Paket hello diterima -> kirim DBD sebagai respons ke source IP di layer IP 
       src_ip_of_neighbor = packet[IP].src
    #    ospf_hello.neighbors = src_ip_of_neighbor  # Simpan neighbor router IP
    #    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received HELLO from {src_ip_of_neighbor}, sending DBD...")
       if neighbor_state == "Down":
            neighbor_state = "2-Way"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received HELLO from {src_ip_of_neighbor}, moving to 2-Way")
            neighbor_ip = src_ip_of_neighbor
            print(f" {ospf_hello.neighbors}")
            sendp(ospf_packet2, iface=interface, verbose=0)
            print(f"Sent OSPF Hello packet at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
            send_ospf_dbd_first(src_ip_of_neighbor, ["I", "M", "MS"], dbd_seq_num)
       elif neighbor_state == "Full":
            if src_ip_of_neighbor == "10.10.1.1":
                ospf_header1 = OSPF_Hdr(version=2, type=1, src=router_id2, area=area_id)
                ospf_packet3 = eth / ip / ospf_header1 / ospf_hellofull
                sendp(ospf_packet3, iface=interface, verbose=0)
                print(f"Sent OSPF Hello packet at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")

   elif ospfhdr_layer.type == 2:  # DBD Packet
        dbd_layer = packet.getlayer(OSPF_DBDesc)
        src_ip_of_neighbor = packet[IP].src
        
        if neighbor_state == "2-Way":
            print(f"haha")
            if "I" in dbd_layer.dbdescr:
                    print(f"masuk")
                    if src_ip_of_neighbor == neighbor_ip:
                        master = True
                        neighbor_state = "ExStart"
                        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received DBD from {src_ip_of_neighbor}, moving to ExStart (Master)")
                        dbd_seq_num_neighbor = dbd_layer.ddseq
                        if src_ip_of_neighbor == '10.10.1.2':
                            # send_ospf_dbd(neighbor_ip)
                            send_ospf_dbd_first(neighbor_ip, ["MS"], dbd_seq_num_neighbor)
                        else:
                            # send_ospf_dbd(src_ip_of_neighbor)
                            send_ospf_dbd_first(src_ip_of_neighbor, ["MS"], dbd_seq_num_neighbor)

                    else:
                        master = False
                        neighbor_state = "ExStart"
                        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received DBD from {src_ip_of_neighbor}, moving to ExStart (Slave)")
                        dbd_seq_num_neighbor = dbd_layer.ddseq
                        if src_ip_of_neighbor == '10.10.1.2':
                            send_ospf_dbd_first(neighbor_ip, ["MS"], dbd_seq_num_neighbor)
                        else:
                            send_ospf_dbd_first(src_ip_of_neighbor, ["MS"], dbd_seq_num_neighbor)
        
        elif neighbor_state == "ExStart":
            if "MS" in dbd_layer.dbdescr:
                if master:
                    if src_ip_of_neighbor == '10.10.1.1':
                        neighbor_state = "Exchange"
                        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received DBD from {src_ip_of_neighbor}, moving to Exchange (Master)")
                        if src_ip_of_neighbor == '10.10.1.2':
                            send_ospf_dbd(neighbor_ip)
                        else:
                            send_ospf_dbd(src_ip_of_neighbor)
                    else:
                        return
                else:
                    if src_ip_of_neighbor == '10.10.1.1':
                        neighbor_state = "Exchange"
                        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received DBD from {src_ip_of_neighbor}, moving to Exchange (Slave)")
                        if src_ip_of_neighbor == '10.10.1.2':
                            send_ospf_dbd(neighbor_ip)
                        else:
                            send_ospf_dbd(src_ip_of_neighbor)
                    else:
                        return
        elif neighbor_state == "Exchange":
            if "M" in dbd_layer.dbdescr:
                if src_ip_of_neighbor == '10.10.1.1':
                    neighbor_state = "Loading"
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received DBD from {src_ip_of_neighbor}, moving to Loading")
                    send_ospf_lsr(src_ip_of_neighbor)

   elif ospfhdr_layer.type == 3:  # LSR Packet
        # lsr_layer = packet.getlayer(OSPF_LSReq)
        src_ip_of_neighbor = packet[IP].src
        
        if neighbor_state == "Loading":
            if src_ip_of_neighbor == '10.10.1.1':
                send_ospf_lsu(src_ip_of_neighbor)
                neighbor_state = "Full"
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received LSR from {src_ip_of_neighbor}, moving to Full")
    
   elif ospfhdr_layer.type == 4:  # LSU Packet
        src_ip_of_neighbor = packet[IP].src
        lsu_layer = packet.getlayer(OSPF_LSUpd)
        print(f"LSU Layer: {lsu_layer}")
        lsu_id = lsu_layer.lsalist[0].id
        print(f"LSU ID: {lsu_id}")
        lsu_adrouter = lsu_layer.adrouter
        lsu_seq = lsu_layer.seq

        # neighbor_state = "Loading"
        
        if neighbor_state == "Loading":
            if src_ip_of_neighbor == '10.10.1.1':
                neighbor_state = "Full"
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received LSU from {src_ip_of_neighbor}, moving to Full")
                send_ospf_lsaack(ipbroadcast)
        if neighbor_state == "Full":
            if src_ip_of_neighbor == '10.10.1.1':
                ospf_lsackfull = OSPF_Hdr(version=2, type=5, src=router_id2, area=area_id)
                
                ospf_lsack_full = (
                OSPF_LSAck(
                    lsaheaders=[
                    OSPF_LSA_Hdr(
                    age=360,
                    options=0x02,
                    type=1,
                    id=lsu_id,
                    adrouter=lsu_adrouter,
                    seq=lsu_seq
                            )
                        ]
                    )
                )
                ospf_lsack2 = eth / ip / ospf_lsackfull / ospf_lsack_full
                sendp(ospf_lsack2, iface=interface, verbose=0)
                print(f"Sent OSPF Hello packet at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
                #  ospf_lsackfull = OSPF_Hdr(version=2, type=5, src=router_id2, area=area_id)
                #  sendp(ospf_lsack_full, iface=interface, verbose=0)
                # send_ospf_lsu(src_ip_of_neighbor)
   
   elif ospfhdr_layer.type == 5: #LSAck Packet
        lsack_layer = packet.getlayer(OSPF_LSAck)
        src_ip_of_neighbor = packet[IP].src
        if neighbor_state == "Full":
            if src_ip_of_neighbor == '10.10.1.1':
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received LSAck from {src_ip_of_neighbor}")
                send_ospf_lsaack(ipbroadcast)

def sniff_packets():
   print("Sniffing packets...")
   sniff(iface=interface , filter="ip proto ospf", prn=lambda pkt: handle_incoming_packet(pkt), store=False, timeout=100000000)
   

if __name__ == "__main__":
   
   hello_thread = threading.Thread(target=lambda : send_ospf_hello_periodically(10))
   hello_thread.daemon=True
   hello_thread.start()
   
   recv_thread = threading.Thread(target=lambda : sniff_packets())
   recv_thread.daemon=True
   recv_thread.start()
   
   try:
      while True:
          time.sleep(1)
          
   except KeyboardInterrupt:
      print("Program terminated by user.")
