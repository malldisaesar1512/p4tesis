from os import link
import os
from socket import timeout
from scapy.all import *
from scapy.contrib.ospf import *
import time
import threading
import random
import psutil
import socket
import ipaddress

#global variable
neighbor_state = "Down"
option_default = 0x02
default_age = 1
hello_interval = 10
dead_interval = 40
priority_default = 128
broadcast_ip = "224.0.0.5"
area_id = "0.0.0.0"
seq_random = random.randint(1000000, 5000000)
seq_exchange = 0
router_status = "Master"
id_dbd = ''
router_id = "10.10.1.2"  # Router ID
router_id2 = "192.168.1.2"  # Router ID 2 (Neighbor)
# area_id = "0.0.0.0"        # Area ID
interface = "ens5"         # Network interface
backup_default = "0.0.0.0"
neighbor_default = "10.10.2.1"
dr = "10.10.1.2"
bdr = "10.10.1.1"
lsadb_list = []
lsreq_list = []
lsreqdb_list = []
lsudb_list = []
lsack_list = []
lsackdb_list = []
a = []
b = []
lsacknih = []
LSA_listdb = []
# interface = []
list_interface = []
list_ip = []
list_netmask = []
list_network = []

ospf_link_list = []
lsadb_hdr_default = []

lsadb_link_default = [OSPF_Link(id = "10.10.1.0", data = "10.10.1.0", type = 3, metric = 1), 
                OSPF_Link(id = "192.168.1.0", data = "192.168.1.0", type = 3, metric = 1)]

#Membuat paket Ethernet
eth = Ether()

ip_broadcast = IP(src=router_id, dst="224.0.0.5")

ospf_header = OSPF_Hdr(version=2, type=1, src=router_id2, area=area_id)

ospf_hello_first = OSPF_Hello(
    mask="255.255.255.0",
    hellointerval=hello_interval,
    options=option_default,
    prio=priority_default,
    deadinterval=dead_interval,
    router=router_id,
    backup= backup_default,  # Backup router ID
    neighbors=[]  # Daftar neighbor IP
)


#TYPE OF LSA_PACKET
lsa_type1 = OSPF_Router_LSA(
            age = 1, # Age of the LSA
            options=0x02, # Options field
            type=1,  # Router LSA
            id="10.10.1.2", # LSA ID
            adrouter="10.10.1.2", # Advertising router
            seq=0x80000123,  # Sequence number
            linkcount=2, # Number of links
            linklist=[] # List of links
        )
lsa_type2 = OSPF_Network_LSA(
            age = 1, # Age of the LSA
            options=option_default, # Options field
            type=2,  # Network LSA
            id="10.10.1.2", # LSA ID
            adrouter="10.10.1.2", # Advertising router
            seq=0x80000124,  # Sequence number
            mask="255.255.255.0", # Subnet mask
            routerlist=[] # List of routers
        )
lsarouter_default = OSPF_LSA_Hdr(
                age = 1,
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

# def get_interfaces_info_separated():
#     global ips, netmasks, networks, statuses
#     addrs = psutil.net_if_addrs()
#     stats = psutil.net_if_stats()

#     interfaces = []  # List untuk menyimpan nama interface
#     ips = []         # List untuk menyimpan IP address
#     netmasks = []    # List untuk menyimpan netmask
#     networks = []    # List untuk menyimpan network address
#     statuses = []    # List untuk menyimpan status interface ("up"/"down")

#     for iface, addr_list in addrs.items():
#         is_up = stats[iface].isup if iface in stats else False
#         for addr in addr_list:
#             if addr.family == socket.AF_INET:
#                 ip = addr.address
#                 netmask = addr.netmask
#                 if ip and netmask and ip != "127.0.0.1" and ip != "10.0.137.31":
#                     network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
#                     network_address = str(network.network_address)  # tanpa prefix
#                     interfaces.append(iface)
#                     ips.append(ip)
#                     netmasks.append(netmask)
#                     networks.append(network_address)
#                     statuses.append("up" if is_up else "down")

#     return interfaces, ips, netmasks, networks, statuses

def get_interfaces_info_with_interface_name():
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    interfaces = []  # List untuk menyimpan data setiap interface sebagai dictionary

    for iface, addr_list in addrs.items():
        is_up = stats[iface].isup if iface in stats else False
        for addr in addr_list:
            i = 0
            if addr.family == socket.AF_INET:
                ip = addr.address
                netmask = addr.netmask
                if ip and netmask and ip != "127.0.0.1" and ip!="10.0.137.31":
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    interface_info = {
                        "interface": iface,
                        "ip_address": ip,
                        "netmask": netmask,
                        "network": f"{network.network_address}/{network.prefixlen}",
                        "status": "up" if is_up else "down",
                        "sequence": seq_random+i
                    }
                    interfaces.append(interface_info)
                    i=i+1

    return interfaces


def send_hello_periodically(interval):
    """Kirim paket Hello OSPF secara berkala"""
    global neighbor_state, neighbor_default, interfaces, ips, netmasks, networks, statuses, lsadb_link_default, lsadb_hdr_default
    while True:
        if neighbor_state == "Down":
            # neighbor_default = ""
            interfaces_info = get_interfaces_info_with_interface_name()
            for info in interfaces_info:
                d = OSPF_Link(id=info['ip_address'], data=info['ip_address'], type=3, metric=1)
                e = OSPF_LSA_Hdr(age=1, options=0x02, type=1, id=info['ip_address'], adrouter=info['ip_address'], seq=info['sequence'])
                
                
                ospf_link_list.append(d)
                lsadb_hdr_default.append(e)

            ospf_hello_first.neighbors = []
            ospf_packet_hello_first = eth / ip_broadcast / ospf_header / ospf_hello_first
            sendp(ospf_packet_hello_first, iface=interface, verbose=0)

            print(f"link list: {ospf_link_list}")
            print(f"LSA list: {lsadb_hdr_default}")
            

            # interfaces, ips, netmasks, networks, statuses = get_interfaces_info_separated()

        # elif neighbor_state == "Full":
        #     ospf_hello_10s = ospf_hello_first
        #     ospf_hello_10s.neighbors = [neighbor_default]
        #     ospf_hello_10s.backup = bdr
        #     ospf_hello_10s.router = dr

        #     ospf_fullhdr = ospf_hello_10s
        #     # print(f"Sent OSPF Hello packet at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
        #     ospf_packet_hello2 = eth / ip_broadcast / ospf_header / ospf_fullhdr
        #     sendp(ospf_packet_hello2, iface=interface, verbose=0)

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
            lsaheaders=lsadb_hdr_default
            # OSPF_LSA_Hdr(
            # age = 1,
            # options=0x02,
            # type=1,
            # id=router_id,
            # adrouter=router_id,
            # seq=0x80000123
            # ),
            # OSPF_LSA_Hdr(
            # age = 1,
            # options=0x02,
            # type=1,
            # id=router_id2,
            # adrouter=router_id2,
            # seq=0x80000124
            # )
        ) 
         
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending DBD packet to {neighbor_router_ip} - Flags: MS ({flag_value}), Seq: {seq_num}")
    sendp(ospf_dbd_pkt2, iface=interface, verbose=True)

def send_ospf_lsr(neighbor_ip):
    global lsreq_list, lsadb_list, a
    """Kirim paket Link State Request (LSR) ke neighbor"""
    # Header IP unicast ke neighbor router IP
    ip_lsr = IP(src=router_id, dst=str(neighbor_ip))
    
    # Header OSPF tipe 3: Link State Request Packet
    ospf_hdr_lsr = OSPF_Hdr(version=2, type=3, src=router_id2, area=area_id)

    for i in lsadb_list:
        # print(f"LSA {i}: {i.show()}") # Menampilkan informasi LSA
        id_lsa = i.id
        adrouter_lsa = i.adrouter
        type_lsa = i.type
        
        if type_lsa == 'router':
            type_lsa = 1
        elif type_lsa == 'network':
            type_lsa = 2

        if id_lsa == router_id2 or id_lsa == router_id:
            continue
        else:
            a = OSPF_LSReq_Item(
            type=type_lsa,
            id=id_lsa,
            adrouter=adrouter_lsa
            )
            lsreq_list.append(a)
        
    print(f"LSR List: {lsreq_list}")
    # Buat LSR packet dengan parameter yang diberikan
    ospf_lsr_pkt = (
        eth /
        ip_lsr /
        ospf_hdr_lsr /
        OSPF_LSReq(
         requests = lsreq_list
        ) 
    )
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending LSR packet to {neighbor_ip}")
    # print(f"LSR List: {lsreq_list}")
    sendp(ospf_lsr_pkt, iface=interface, verbose=0)
    lsreq_list.clear()
    lsadb_list.clear()

def send_ospf_lsu(neighbor_ip):
    global lsudb_list, lsreqdb_list, lsa_type1, lsadb_link_default, jumlah_lsreq, b 
    """Kirim paket Link State Update (LSU) ke neighbor"""
    # Header IP unicast ke neighbor router IP
    ip_lsu = IP(src=router_id, dst=str(neighbor_ip))
    
    # Header OSPF tipe 4: Link State Update Packet
    ospf_hdr_lsu = OSPF_Hdr(version=2, type=4, src=router_id2, area=area_id)

    for i in lsreqdb_list:
        type_lsr = i.type
        id_lsr = i.id
        adrouter_lsr = i.adrouter

        if type_lsr == 'router' or type_lsr == 1:
            lsulist = lsa_type1
            lsulist.linklist = ospf_link_list
            lsulist.id = id_lsr
            lsulist.adrouter = adrouter_lsr
            lsulist.type = type_lsr

            b = lsulist

            lsudb_list.append(b)
        elif type_lsr == 'network' or type_lsr == 2:
            lsulist = lsa_type2
            lsulist.id = id_lsr
            lsulist.adrouter = adrouter_lsr
            lsulist.type = type_lsr
            lsulist.routerlist = ips

            b = lsulist
            lsudb_list.append(b)
        
    print(f"LSU List: {lsudb_list}")
    
    # Buat LSU packet dengan LSAs yang diberikan
    ospf_lsu_pkt = (
        eth /
        ip_lsu /
        ospf_hdr_lsu /
        OSPF_LSUpd(
            lsacount=jumlah_lsreq,
            lsalist= lsudb_list
        )  
        
    )

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending LSU packet to {neighbor_ip}")
    sendp(ospf_lsu_pkt, iface=interface, verbose=0)
    lsudb_list.clear()
    lsreqdb_list.clear()

def send_ospf_lsaack(broadcastip):
    global lsudb_list, lsack_list, lsackdb_list, lsarouter_default, lsacknih
    ip_lsack = IP(src=router_id, dst=str(broadcastip))
    
    # Header OSPF tipe 5: Link State ACK Packet
    ospf_hdr_lsack = OSPF_Hdr(version=2, type=5, src=router_id2, area=area_id)
    
    # Buat LSU packet dengan LSAs yang diberikan

    for i in lsackdb_list:
        lsack_id = i.id
        lsack_adrouter = i.adrouter
        lsack_type = i.type
        lsack_seq = i.seq

        if lsack_id == router_id2 or lsack_type == 2:
            continue
        else:
            lsacknih = OSPF_LSA_Hdr(
                    age = 1,
                    options=0x02,
                    type=lsack_type,
                    id=lsack_id,
                    adrouter=lsack_adrouter,
                    seq=lsack_seq
                )
            lsack_list.append(lsacknih)
            print(f"LSA {i}: {lsacknih}") # Menampilkan informasi LSA
        
    # print(f"lsack.list: {lsack_list}")

    ospf_lsack_pkt = (
        eth /
        ip_lsack /
        ospf_hdr_lsack /
                OSPF_LSAck(
                    lsaheaders = lsack_list
        )
    )
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending LS_ACK packet to {broadcastip}")
    sendp(ospf_lsack_pkt, iface=interface, verbose=0)
    lsackdb_list.clear()
    lsack_list.clear()

def handle_incoming_packet(packet):
    """Fungsi untuk menangani paket yang diterima"""
    global neighbor_state, dbd_seq_num, seq_exchange, lsackdb_list, router_status, eth, ip_broadcast, ospf_header, ospf_hello_pkt, lsadb_list, jumlah_lsa, jumlah_lsreq, lsreq_list, lsreqdb_list, jumlah_lsulsa, lsudb_list

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
                    # ospf_hello_first.backup = src_ip
                    ospf_hello_first.neighbors = [neighbor_ip]
                    ospf_packet_hello2 = eth / ip_broadcast / ospf_header / ospf_hello_first
                    sendp(ospf_packet_hello2, iface=interface, verbose=0)
                    send_ospf_dbd_first(src_ip, seq_random)
                    # print(f"{ospf_packet_hello2.show()}")
                    print(f"Sent OSPF Hello packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
            elif neighbor_state == "Full":
                if src_ip != router_id:
                    print("Received Hello packet")
                    neighbor_state = "Full"
                    neighbor_ip = src_neighbor
                    ospf_hello_full = ospf_hello_first
                    ospf_hello_full.neighbors = [neighbor_ip]
                    ospf_hello_full.backup = [ospfhdr_layer.backup]
                    ospf_hello_full.router = [ospfhdr_layer.router]
                    # ospf_hello_first.backup = src_ip
                    # ospf_hello_first.neighbors = [neighbor_ip]
                    ospf_packet_hellofull = ospf_hello_full
                    ospf_packet_hello2 = eth / ip_broadcast / ospf_header / ospf_packet_hellofull
                    sendp(ospf_packet_hello2, iface=interface, verbose=0)
                    # print(f"{ospf_packet_hello2.show()}")
                    print(f"Sent OSPF Hello packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
        elif ospfhdr_layer.type == 2:  # DBD packet
            src_ip = packet[IP].src

            # if neighbor_state == "2-Way":
            #     if src_ip != router_id:
            #         print("Received DBD packet")
            #         neighbor_state = "Exstart"
            #         print(f"Received DBD from {src_ip}, moving to Exstart state")
            #         send_ospf_dbd_first(src_ip, seq_random)
            #         print(f"Sent DBD packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
                # neighbor_state = "Exstart"
                # print(f"Received DBD from {src_ip}, moving to Exstart state")
                # send_ospf_dbd_first(src_ip, seq_random)
            if neighbor_state == "2-Way":
                if src_ip != router_id:
                    dbd_layer = packet.getlayer(OSPF_DBDesc)
                    if dbd_layer.dbdescr == 0x00:
                        jumlah_lsa = len(dbd_layer.lsaheaders)
                        print(f"{dbd_layer.show()}")
                        print(f"Jumlah LSA: {jumlah_lsa}")
                        router_status = "Master"
                        print(f"{router_status} DBD")
                        seq_exchange = dbd_layer.ddseq
                        print(f"Received DBD from {src_ip}, moving to Exchange state as Master")
                        neighbor_state = "Exchange"
                        # send_ospf_dbd_first(src_ip, seq_random)
                        send_ospf_dbd(src_ip)
                        print(f"Sent DBD packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
                    else:
                        return
                        router_status = "Slave"
                        print(f"{router_status} DBD")
                        seq_exchange = dbd_layer.ddseq
                        print(f"Received DBD from {src_ip}, moving to Exchange state as Slave")
                        neighbor_state = "Exchange"
                        # send_ospf_dbd_first(src_ip, seq_random)
                        send_ospf_dbd(src_ip)
                        print(f"Sent DBD packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
                    
                    for i in range(jumlah_lsa): #add LSA to list
                        lsa = dbd_layer.lsaheaders[i]
                        lsadb_list.append(lsa)
                    #     print(f"LSA {i+1}: ID: {lsa.id}, Type: {lsa.type}, Advertising Router: {lsa.adrouter}, Sequence Number: {lsa.seq}")
                    # print(f"LSA List: {lsadb_list}")
                    send_ospf_lsr(src_ip) #kirim LSR ke neighbor

        elif ospfhdr_layer.type == 3:  # LSR packet
            print("Received LSR packet")
            print(f"{lsadb_list}")
            src_ip = packet[IP].src
            if neighbor_state == "Exchange":
                if src_ip != router_id:
                    lsr_layer = packet.getlayer(OSPF_LSReq)
                    jumlah_lsreq = len(lsr_layer.requests)
                    print(f"Received LSR from {src_ip}, ready to Full state")
                    neighbor_state = "Loading"

                    for i in range(jumlah_lsreq):
                        lsr = lsr_layer.requests[i]
                        lsreqdb_list.append(lsr)
                        # print(f"LSR {i+1}: ID: {lsr.id}, Type: {lsr.type}, Advertising Router: {lsr.adrouter}")

                    send_ospf_lsu(src_ip)
                    print(f"Sent LSU packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")


        elif ospfhdr_layer.type == 4:  # LSU packet
            print("Received LSU packet")
            src_ip = packet[IP].src
            if neighbor_state == "Loading":
                if src_ip != router_id:
                    lsu_layer = packet.getlayer(OSPF_LSUpd)
                    jumlah_lsulsa = lsu_layer.lsacount
                    print(f"Received LSU from {src_ip}, moving to Full state")
                    neighbor_state = "Full"
                    for i in range(jumlah_lsulsa):
                        lsalsu = lsu_layer.lsalist[i]
                        lsackdb_list.append(lsalsu)
                        # print(f"LSU {i+1}: ID: {lsalsu.id}, Type: {lsalsu.type}, Advertising Router: {lsalsu.adrouter}")
                    # print(f"LSA List: {len(lsackdb_list)}")
                    send_ospf_lsaack(broadcast_ip)
                    print(f"Sent LS_ACK packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
            if neighbor_state == "Full":
                if src_ip != router_id:
                    lsu_layer = packet.getlayer(OSPF_LSUpd)
                    jumlah_lsulsa = lsu_layer.lsacount
                    print(f"Received LSU from {src_ip}, moving to Full state")
                    neighbor_state = "Full"
                    for i in range(jumlah_lsulsa):
                        lsalsu = lsu_layer.lsalist[i]
                        lsackdb_list.append(lsalsu)
                        # print(f"LSU {i+1}: ID: {lsalsu.id}, Type: {lsalsu.type}, Advertising Router: {lsalsu.adrouter}")
                    # print(f"LSA List: {len(lsackdb_list)}")
                    send_ospf_lsaack(broadcast_ip)
                    print(f"Sent LS_ACK packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
        elif ospfhdr_layer.type == 5:  # LSAck packet
            print("Received LSAck packet")
            src_ip = packet[IP].src
            if neighbor_state == "Full":
                if src_ip != router_id:
                    # lsack_layer = packet.getlayer(OSPF_LSAck)
                    # jumlah_lsack = len(lsack_layer.lsaheaders)
                    print(f"Received LSAck from {src_ip}, moving to Full state")
                    neighbor_state = "Full"
                    send_ospf_lsaack(broadcast_ip)

def sniff_packets():
   print("Sniffing packets...")
   sniff(iface=interface , filter="ip proto ospf", prn=lambda pkt: handle_incoming_packet(pkt), store=False, timeout=100000000)

if __name__ == "__main__":
   
   hello_thread = threading.Thread(target=lambda : send_hello_periodically(10))
   hello_thread.daemon=True
   hello_thread.start()
   
#    recv_thread = threading.Thread(target=lambda : sniff_packets())
#    recv_thread.daemon=True
#    recv_thread.start()
   
   try:
      while True:
          time.sleep(1)
          
   except KeyboardInterrupt:
      print("Program terminated by user.")