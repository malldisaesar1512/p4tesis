from os import link
from socket import timeout
from scapy.all import *
from scapy.contrib.ospf import *
import time
import threading
import random

#global variable
neighbor_state = "Down"
default_age = 360
hello_interval = 10
dead_interval = 40
priority_default = 128
broadcast_ip = "224.0.0.5"
area_id = "0.0.0.0"
seq_random = random.randint(100000, 500000)
seq_exchange = 0
router_status = "Master"
id_dbd = ''
router_id = "10.10.1.2"  # Router ID
router_id2 = "192.168.1.1"  # Router ID 2 (Neighbor)
# area_id = "0.0.0.0"        # Area ID
interface = "ens5"         # Network interface
backup_default = "0.0.0.0"
neighbor_default = "10.10.1.1"


#Membuat paket Ethernet
eth = Ether()

ip_broadcast = IP(src=router_id, dst="224.0.0.5")

ospf_header = OSPF_Hdr(version=2, type=1, src=router_id2, area=area_id)

ospf_hello_first = OSPF_Hello(
    mask="255.255.255.0",
    hellointerval=hello_interval,
    options=0x02,
    prio=priority_default,
    deadinterval=dead_interval,
    router=router_id,
    backup= backup_default,  # Backup router ID
    neighbors=[]  # Daftar neighbor IP
)


#TYPE OF LSA_PACKET
lsa_type1 = OSPF_Router_LSA(
            age=360, # Age of the LSA
            options=0x02, # Options field
            type=1,  # Router LSA
            id="10.10.1.2", # LSA ID
            adrouter="10.10.1.2", # Advertising router
            seq=0x80000123,  # Sequence number
            linkcount=2, # Number of links
            linklist=[] # List of links
        )
lsa_type2 = OSPF_Network_LSA(
            age=360, # Age of the LSA
            options=0x02, # Options field
            type=2,  # Network LSA
            id="10.10.1.2", # LSA ID
            adrouter="10.10.1.2", # Advertising router
            seq=0x80000124,  # Sequence number
            mask="255.255.255.0", # Subnet mask
            routerlist=[] # List of routers
        )
lsa_default = OSPF_LSA_Hdr(
                age=360,
                options=0x02,
                type=1,
                id=router_id2,
                adrouter=router_id2,
                seq=0x80000124
            )

lsa_link = OSPF_Link( #LinkLSA
                type=1,
                id=router_id2,
                data=router_id2,
                metric=10
            )

# # Variabel untuk melacak state neighbor
# neighbor_state = "Down"
# neighbor_ip = router_id2
# dbd_seq_num = random.randint(100000, 500000)
# dbd_seq_num_neighbor = None
# master = False

# # Membuat paket Ethernet
# eth = Ether()

# # Membuat header OSPF (versi 2, tipe 1=Hello)
# ospf_header = OSPF_Hdr(version=2, type=1, src=router_id2, area=area_id)

# ospf_packet_hello_first = eth / ip_broadcast / ospf_header / ospf_hello_first

def send_hello_periodically(interval):
    """Kirim paket Hello OSPF secara berkala"""
    global neighbor_state, neighbor_default
    while True:
        if neighbor_state == "Down":
            # neighbor_default = ""
            ospf_hello_first.neighbors = []
            ospf_packet_hello_first = eth / ip_broadcast / ospf_header / ospf_hello_first
            sendp(ospf_packet_hello_first, iface=interface, verbose=0)
        elif neighbor_state == "Full" or neighbor_state == "2-Way":
            ospf_hello_first.neighbors = [neighbor_default]
            # print(f"Sent OSPF Hello packet at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
        print(f"Sent OSPF Hello packet at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
        time.sleep(interval)

def send_ospf_dbd_first(neighbor_ip, seq_num):
    """Kirim paket Database Description (DBD) pertama ke neighbor dengan flags dan seq_num yang benar"""
    ip_dbd = IP(src=router_id, dst=str(neighbor_ip))
    ospf_hdr_dbd = OSPF_Hdr(version=2, type=2, src=router_id2, area=area_id)
    
    # Konversi list flags string ke bitmask integer
    # flag_value = 0
    # if "I" in flags:
    #     flag_value |= 0x04  # Init bit
    # if "M" in flags:
    #     flag_value |= 0x02  # More bit
    # if "MS" in flags:
    #     flag_value |= 0x01  # Master/Slave bit
    
    ospf_dbd_pkt1 = (
        eth /
        ip_dbd /
        ospf_hdr_dbd /
        OSPF_DBDesc(
            options=0x02,
            mtu=1500,
            dbdescr=0x07,
            ddseq=seq_num,
            lsaheaders=[]
        )
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending DBD FIRST packet to {neighbor_ip} -  Seq: {seq_num}")
    sendp(ospf_dbd_pkt1, iface=interface, verbose=0)

def send_ospf_dbd(neighbor_router_ip):
    """Kirim paket Database Description (DBD) lanjutan ke neighbor dengan flags dan seq_num yang benar"""
    ip_dbd = IP(src=router_id, dst=str(neighbor_router_ip))
    ospf_hdr_dbd = OSPF_Hdr(version=2, type=2, src=router_id2, area=area_id)
    
    # Flags More + Master/Slave (tanpa Init)
    flag_value = 0x01  #MS
    
    # Pastikan dbd_seq_num_neighbor sudah terisi dan bertambah 1
    seq_num = seq_exchange + 1 if seq_exchange is not None else seq_random + 1
    
    ospf_dbd_pkt2 = (
        eth /
        ip_dbd /
        ospf_hdr_dbd /
        OSPF_DBDesc(
            options=0x02,
            mtu=1500,
            dbdescr=flag_value,
            ddseq=seq_num,
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

def handle_incoming_packet(packet):
    """Fungsi untuk menangani paket yang diterima"""
    global neighbor_state, dbd_seq_num, seq_exchange, router_status, eth, ip_broadcast, ospf_header, ospf_hello_pkt

    # Cek apakah paket adalah paket OSPF
    if packet.haslayer(OSPF_Hdr):
        ospf_hdr = packet[OSPF_Hdr]
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received OSPF packet: {ospf_hdr.summary()}")

        if not packet.haslayer(OSPF_Hdr):
            print("Not an OSPF packet")
            return

        ospfhdr_layer = packet.getlayer(OSPF_Hdr)
        # Cek tipe paket OSPF
        if ospfhdr_layer.type == 1:  # Hello packet
            src_ip = packet[IP].src
            src_neighbor = packet[OSPF_Hdr].src


            if neighbor_state == "Down":
                if src_ip != router_id:
                    print("Received Hello packet")
                    neighbor_state = "Init"
                    neighbor_ip = src_neighbor
                    print(f"Received Hello from {src_ip}, moving to Init state or 2-Way")
                    ospf_hello_first.neighbors = [neighbor_ip]
                    ospf_packet_hello2 = eth / ip_broadcast / ospf_header / ospf_hello_first
                    sendp(ospf_packet_hello2, iface=interface, verbose=0)
                    # print(f"{ospf_packet_hello2.show()}")
                    print(f"Sent OSPF Hello packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
            elif neighbor_state == "Init":
                if src_ip != router_id:
                    print("Received Hello packet")
                    neighbor_state = "2-Way"
                    neighbor_ip = src_neighbor
                    print(f"Received Hello from {src_ip}, moving to 2-Way state")
                    ospf_hello_first.backup = src_ip
                    ospf_hello_first.neighbors = [neighbor_ip]
                    ospf_packet_hello2 = eth / ip_broadcast / ospf_header / ospf_hello_first
                    sendp(ospf_packet_hello2, iface=interface, verbose=0)
                    # print(f"{ospf_packet_hello2.show()}")
                    print(f"Sent OSPF Hello packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
        elif ospfhdr_layer.type == 2:  # DBD packet
            dbd_layer = packet.getlayer(OSPF_DBDesc)
            src_ip = packet[IP].src

            if neighbor_state == "2-Way":
                if src_ip != router_id:
                    print("Received DBD packet")
                    neighbor_state = "Exstart"
                    print(f"Received DBD from {src_ip}, moving to Exstart state")
                    send_ospf_dbd_first(src_ip, seq_random)
                    print(f"Sent DBD packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
                # neighbor_state = "Exstart"
                # print(f"Received DBD from {src_ip}, moving to Exstart state")
                # send_ospf_dbd_first(src_ip, seq_random)
            elif neighbor_state == "Exstart":
                if src_ip != router_id:
                    if 0x00 in dbd_layer.dbdescr:
                        router_status = "Master"
                        seq_exchange = dbd_layer.ddseq
                        print(f"Received DBD from {src_ip}, moving to Exchange state as Master")
                        neighbor_state = "Exchange"
                        send_ospf_dbd_first(src_ip, seq_random)
                        print(f"Sent DBD packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
                    else:
                        router_status = "Slave"
                        seq_exchange = dbd_layer.ddseq
                        print(f"Received DBD from {src_ip}, moving to Exchange state as Slave")
                        neighbor_state = "Exchange"
                        send_ospf_dbd_first(src_ip, seq_random)
                        print(f"Sent DBD packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
            elif neighbor_state == "Exchange":
                if src_ip != router_id:
                    if router_status == "Master":
                        print(f"Received DBD from {src_ip}, moving to Loading state as Master")
                        neighbor_state = "Loading"
                        send_ospf_dbd(src_ip)
                        print(f"Sent DBD packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
                    else:
                        print(f"Received DBD from {src_ip}, moving to Loading state as Slave")
                        neighbor_state = "Loading"
                        send_ospf_dbd(src_ip)
                        print(f"Sent DBD packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
            
            
                
                # send_ospf_lsr(src_neighbor)
            # neighbor_state = "2-Way"
            # dbd_seq_num_neighbor = ospf_hdr.seq
            # master = True
        elif ospfhdr_layer.type == 3:  # LSR packet
            print("Received LSR packet")
            neighbor_state = "ExStart"
        elif ospfhdr_layer.type == 4:  # LSU packet
            print("Received LSU packet")
        elif ospfhdr_layer.type == 5:  # LSAck packet
            print("Received LSAck packet")

def sniff_packets():
   print("Sniffing packets...")
   sniff(iface=interface , filter="ip proto ospf", prn=lambda pkt: handle_incoming_packet(pkt), store=False, timeout=100000000)

if __name__ == "__main__":
   
   hello_thread = threading.Thread(target=lambda : send_hello_periodically(10))
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