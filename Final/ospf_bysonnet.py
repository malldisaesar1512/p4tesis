from scapy.all import *
from scapy.contrib.ospf import *
import time
import threading
import random
import psutil
import socket
import ipaddress
import subprocess
from datetime import datetime

# Global variables
neighbor_state = "Down"
penghitung = 0
option_default = 0x02
default_age = 3300
hello_interval = 10
dead_interval = 40
priority_default = 1
broadcast_ip = "224.0.0.5"
area_id = "0.0.0.0"
seq_random = random.randint(1000000, 5000000)
seq_exchange = 0
router_status = "Master"
router_id = "10.10.1.2"
router_id2 = "192.168.1.2"
backup_default = "0.0.0.0"
neighbor_default = "10.10.2.1"
dr = "10.10.1.2"
bdr = "10.10.1.1"

# Lists and dictionaries
lsadb_list = []
lsreq_list = []
lsreqdb_list = []
lsudb_list = []
lsack_list = []
lsackdb_list = []
lsulist = None
lsacknih = []
LSA_listdb = []
newrute = []
rutep4 = []
list_interface = []
list_ip = []
list_netmask = []
list_network = []
neighbors_state = {}
tracking_state = {}
db_lsap4 = {}
target_ip = ipaddress.IPv4Address("0.0.0.0")

ospf_link_list = []
lsadb_hdr_default = []

# Default OSPF Hello packet structure
ospf_hello_first = OSPF_Hello(
    mask="255.255.255.0",
    hellointerval=hello_interval,
    options=option_default,
    prio=priority_default,
    deadinterval=dead_interval,
    router=router_id,
    backup=backup_default,
    neighbors=[]
)

# LSA structures
lsa_type1 = OSPF_Router_LSA(
    age=3300,
    options=0x02,
    type=1,
    id="10.10.1.2",
    adrouter="10.10.1.2",
    seq=0x80000123,
    linkcount=2,
    linklist=[]
)

lsa_type2 = OSPF_Network_LSA(
    age=3300,
    options=option_default,
    type=2,
    id="10.10.1.2",
    adrouter="10.10.1.2",
    seq=0x80000124,
    mask="255.255.255.0",
    routerlist=[]
)

def get_interfaces_info_with_interface_name():
    """Get network interface information"""
    global ips, netmasks, networks, statuses, interfaces_info, networklist
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    interfaces = []
    ips = []
    networklist = []
    h = 0
    
    for iface, addr_list in addrs.items():
        is_up = stats[iface].isup if iface in stats else False
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ip = addr.address
                netmask = addr.netmask
                if ip and netmask and ip != "127.0.0.1" and ip != "10.0.137.31":
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    network_pre = f"{network.network_address}/{network.prefixlen}"
                    network_address = str(network.network_address)
                    if network_pre in networklist and ip in ips:
                        continue
                    else:
                        networklist.append(network_pre)
                        ips.append(ip)
                    interface_info = {
                        "interface": iface,
                        "ip_address": ip,
                        "netmask": netmask,
                        "network": network_address,
                        "status": "up" if is_up else "down",
                        "sequence": seq_random+h
                    }
                    interfaces.append(interface_info)
                    h = h + 1
    return interfaces

def send_hello_periodically(interval, interface, ip_address, source_ip):
    """Send OSPF Hello packets periodically - Layer 3"""
    global neighbor_state, neighbor_default, interfaces_info, totallink, seq_global, e
    
    while True:
        interfaces_info = get_interfaces_info_with_interface_name()
        for info in interfaces_info:
            if info["interface"] == "ens4":
                d = OSPF_Link(id=info['network'], data=info['netmask'], type=3, metric=1)
            else:
                d = OSPF_Link(id=info['ip_address'], data=info['ip_address'], type=2, metric=1)

            if info["interface"] == "ens4":
                e = OSPF_LSA_Hdr(age=1, options=0x02, type=1, id=info['ip_address'], adrouter=info['ip_address'], seq=info['sequence'])
                seq_global = info['sequence']

            if d in ospf_link_list and e in lsadb_hdr_default:
                continue
            else:
                ospf_link_list.append(d)
                lsadb_hdr_default.append(e)

        if neighbor_state == "Down":
            # Layer 3 packet construction (no Ethernet header)
            ip_broadcast_hello = IP(src=ip_address, dst=broadcast_ip)
            ospf_header = OSPF_Hdr(version=2, type=1, src=source_ip, area=area_id)
            ospf_hello_first.neighbors = []
            ospf_hello_first.router = ip_address
            
            # Use send() instead of sendp() for Layer 3
            ospf_packet_hello_first = ip_broadcast_hello / ospf_header / ospf_hello_first
            send(ospf_packet_hello_first, iface=interface, verbose=0)

        totallink = len(ospf_link_list)
        print(f"neighbors_state: {tracking_state}")
        print(f"ospf_link_list: {ospf_link_list}")
        print(f"lsadb_hdr_default: {lsadb_hdr_default}")
        print(f"Sent OSPF Hello packet at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
        time.sleep(interval)

def send_ospf_dbd_first(interface, src_broadcast, source_ip, neighbor_ip, seq_num):
    """Send first Database Description packet - Layer 3"""
    # Layer 3 packet construction
    ip_dbd = IP(src=src_broadcast, dst=str(neighbor_ip))
    ospf_hdr_dbd = OSPF_Hdr(version=2, type=2, src=source_ip, area=area_id)
    
    ospf_dbd_pkt1 = (
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
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending DBD FIRST packet to {neighbor_ip} - Seq: {seq_num}")
    send(ospf_dbd_pkt1, iface=interface, verbose=0)

def send_ospf_dbd(interface, src_broadcast, source_ip, neighbor_router_ip):
    """Send Database Description packet - Layer 3"""
    ip_dbd = IP(src=src_broadcast, dst=str(neighbor_router_ip))
    ospf_hdr_dbd = OSPF_Hdr(version=2, type=2, src=source_ip, area=area_id)
    
    flag_value = 0x01  # MS flag
    seq_num = seq_exchange + 1 if seq_exchange is not None else seq_random + 1
    
    ospf_dbd_pkt2 = (
        ip_dbd /
        ospf_hdr_dbd /
        OSPF_DBDesc(
            options=0x02,
            mtu=1500,
            dbdescr=flag_value,
            ddseq=seq_num,
            lsaheaders=lsadb_hdr_default
        )
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending DBD packet to {neighbor_router_ip} - Flags: MS ({flag_value}), Seq: {seq_num}")
    send(ospf_dbd_pkt2, iface=interface, verbose=0)

def send_ospf_lsr(interface, src_broadcast, source_ip, neighbor_ip):
    """Send Link State Request packet - Layer 3"""
    global lsreq_list, lsadb_list, a
    
    ip_lsr = IP(src=src_broadcast, dst=str(neighbor_ip))
    ospf_hdr_lsr = OSPF_Hdr(version=2, type=3, src=source_ip, area=area_id)

    for i in lsadb_list:
        id_lsa = i.id
        adrouter_lsa = i.adrouter
        type_lsa = i.type
        
        if type_lsa == 'router':
            type_lsa = 1
        elif type_lsa == 'network':
            type_lsa = 2

        if id_lsa not in [info['ip_address'] for info in interfaces_info]:
            a = OSPF_LSReq_Item(
                type=type_lsa,
                id=id_lsa,
                adrouter=adrouter_lsa
            )
            lsreq_list.append(a)

    ospf_lsr_pkt = (
        ip_lsr /
        ospf_hdr_lsr /
        OSPF_LSReq(requests=lsreq_list)
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending LSR packet to {neighbor_ip}")
    send(ospf_lsr_pkt, iface=interface, verbose=0)
    lsreq_list.clear()
    lsadb_list.clear()

def send_ospf_lsu(interface, src_broadcast, source_ip, neighbor_ip):
    """Send Link State Update packet - Layer 3"""
    global lsudb_list, lsreqdb_list, lsa_type1, lsadb_link_default, jumlah_lsreq, b, lsulist
    
    ip_lsu = IP(src=src_broadcast, dst=str(neighbor_ip))
    ospf_hdr_lsu = OSPF_Hdr(version=2, type=4, src=source_ip, area=area_id)

    for i in lsreqdb_list:
        type_lsr = i.type
        id_lsr = i.id
        adrouter_lsr = i.adrouter

        # Find sequence number for this LSA
        seq_lsr = seq_random
        for info in interfaces_info:
            if info['ip_address'] == id_lsr:
                seq_lsr = info['sequence']

        if type_lsr in ['router', '1', 1]:
            lsulist = OSPF_Router_LSA(
                age=3300,
                options=0x02,
                type=1,
                id=id_lsr,
                adrouter=adrouter_lsr,
                seq=seq_lsr,
                linkcount=totallink,
                linklist=ospf_link_list
            )
            lsudb_list.append(lsulist)

        elif type_lsr in ['network', 2]:
            lsulist = OSPF_Network_LSA(
                age=3300,
                options=option_default,
                type=2,
                id=id_lsr,
                adrouter=adrouter_lsr,
                seq=seq_lsr,
                mask="255.255.255.0",
                routerlist=ips
            )
            lsudb_list.append(lsulist)

    ospf_lsu_pkt = (
        ip_lsu /
        ospf_hdr_lsu /
        OSPF_LSUpd(
            lsacount=jumlah_lsreq,
            lsalist=lsudb_list
        )
    )

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending LSU packet to {neighbor_ip}")
    send(ospf_lsu_pkt, iface=interface, verbose=0)
    lsudb_list.clear()
    lsreqdb_list.clear()

def send_ospf_lsaack(interface, src_broadcast, source_ip, broadcastip):
    """Send Link State Acknowledgment packet - Layer 3"""
    global lsudb_list, lsack_list, lsackdb_list, lsacknih, newrute, mac_src, networklist
    
    ip_lsack = IP(src=src_broadcast, dst=str(broadcastip))
    ospf_hdr_lsack = OSPF_Hdr(version=2, type=5, src=source_ip, area=area_id)

    for i in lsackdb_list:
        lsack_id = i.id
        lsack_adrouter = i.adrouter
        lsack_type = i.type
        lsack_seq = i.seq

        lsacknih = OSPF_LSA_Hdr(
            age=3300,
            options=0x02,
            type=lsack_type,
            id=lsack_id,
            adrouter=lsack_adrouter,
            seq=lsack_seq
        )
        lsack_list.append(lsacknih)

        # Process network LSAs for routing table
        if lsack_type in ['network', 2]:
            lsdbp4 = i.routerlist if hasattr(i, 'routerlist') else []
            netp4 = i.mask if hasattr(i, 'mask') else "255.255.255.0"
            
            for router_ip in lsdbp4:
                try:
                    network5 = ipaddress.IPv4Network(f"{router_ip}/{netp4}", strict=False)
                    rute = f"{network5.network_address}/{network5.prefixlen}"
                    print(f"Route: {rute} - Netmask: {netp4} - Interface: {interface}")
                    if rute not in newrute:
                        newrute.append(rute)
                except:
                    continue
            
            db_lsap4[interface] = {
                "routelist": newrute, 
                "netmask": netp4, 
                "interface": interface
            }

    ospf_lsack_pkt = (
        ip_lsack /
        ospf_hdr_lsack /
        OSPF_LSAck(lsaheaders=lsack_list)
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending LS_ACK packet to {broadcastip}")
    send(ospf_lsack_pkt, iface=interface, verbose=0)

    lsackdb_list.clear()
    lsack_list.clear()

def handle_incoming_packet(packet, interface, src_broadcast, source_ip):
    """Handle incoming OSPF packets"""
    global neighbor_state, seq_exchange, lsackdb_list, router_status, lsadb_list, jumlah_lsa, jumlah_lsreq, lsreq_list, lsreqdb_list, jumlah_lsulsa, lsudb_list, penghitung, lsanew, mac_src
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received packet on interface {interface}")
    
    if not packet.haslayer(OSPF_Hdr):
        return

    ospf_hdr = packet[OSPF_Hdr]
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received OSPF packet: {ospf_hdr.summary()}")

    ospfhdr_layer = packet.getlayer(OSPF_Hdr)
    
    # Process different OSPF packet types
    if ospfhdr_layer.type == 1:  # Hello packet
        handle_hello_packet(packet, interface, src_broadcast, source_ip, ospfhdr_layer)
    elif ospfhdr_layer.type == 2:  # DBD packet
        handle_dbd_packet(packet, interface, src_broadcast, source_ip, ospfhdr_layer)
    elif ospfhdr_layer.type == 3:  # LSR packet
        handle_lsr_packet(packet, interface, src_broadcast, source_ip, ospfhdr_layer)
    elif ospfhdr_layer.type == 4:  # LSU packet
        handle_lsu_packet(packet, interface, src_broadcast, source_ip, ospfhdr_layer)

def handle_hello_packet(packet, interface, src_broadcast, source_ip, ospfhdr_layer):
    """Handle OSPF Hello packets"""
    global neighbor_state, ospf_hello_first
    
    src_ip = packet[IP].src
    ip2 = ipaddress.IPv4Address(src_ip)
    ip1 = tracking_state.get(interface, {}).get("ip_address")
    netmask1 = tracking_state.get(interface, {}).get("netmask")
    
    if not ip1 or not netmask1:
        return
        
    network1 = ipaddress.IPv4Network(f"{ip1}/{netmask1}", strict=False)
    src_neighbor = packet[OSPF_Hdr].src
    current_state = tracking_state.get(interface, {}).get("state", "Down")

    if current_state == "Down" and ip2 in network1 and src_ip not in ips:
        print(f"Received Hello from {src_ip}, moving to Init state")
        neighbor_state = "Full"
        tracking_state[interface]["state"] = "Init"
        neighbor_ip = src_neighbor
        
        ospf_hello_first.neighbors = [neighbor_ip]
        ospf_hello_first.router = src_ip
        
        # Layer 3 Hello response
        ip_broadcast_hello = IP(src=src_broadcast, dst=broadcast_ip)
        ospf_header = OSPF_Hdr(version=2, type=1, src=source_ip, area=area_id)
        ospf_packet_hello2 = ip_broadcast_hello / ospf_header / ospf_hello_first
        send(ospf_packet_hello2, iface=interface, verbose=0)
        
        print(f"Sent OSPF Hello packet to {src_ip} - State: {neighbor_state}")

def handle_dbd_packet(packet, interface, src_broadcast, source_ip, ospfhdr_layer):
    """Handle OSPF Database Description packets"""
    global seq_exchange, router_status, lsadb_list, jumlah_lsa
    
    src_ip = packet[IP].src
    ip2 = ipaddress.IPv4Address(src_ip)
    ip1 = tracking_state.get(interface, {}).get("ip_address")
    netmask1 = tracking_state.get(interface, {}).get("netmask")
    
    if not ip1 or not netmask1:
        return
        
    network1 = ipaddress.IPv4Network(f"{ip1}/{netmask1}", strict=False)
    current_state = tracking_state.get(interface, {}).get("state", "Down")

    if current_state == "2-Way" and ip2 in network1 and src_ip not in ips:
        dbd_layer = packet.getlayer(OSPF_DBDesc)
        if dbd_layer.dbdescr == 0x00:
            jumlah_lsa = len(dbd_layer.lsaheaders)
            router_status = "Master"
            seq_exchange = dbd_layer.ddseq
            
            print(f"Received DBD from {src_ip}, moving to Exchange state as Master")
            tracking_state[interface]["state"] = "Exchange"
            
            send_ospf_dbd(interface, src_broadcast, source_ip, src_ip)
            
            for lsa in dbd_layer.lsaheaders:
                lsadb_list.append(lsa)
            
            send_ospf_lsr(interface, src_broadcast, source_ip, src_ip)

def handle_lsr_packet(packet, interface, src_broadcast, source_ip, ospfhdr_layer):
    """Handle OSPF Link State Request packets"""
    global lsreqdb_list, jumlah_lsreq
    
    src_ip = packet[IP].src
    ip2 = ipaddress.IPv4Address(src_ip)
    ip1 = tracking_state.get(interface, {}).get("ip_address")
    netmask1 = tracking_state.get(interface, {}).get("netmask")
    
    if not ip1 or not netmask1:
        return
        
    network1 = ipaddress.IPv4Network(f"{ip1}/{netmask1}", strict=False)
    current_state = tracking_state.get(interface, {}).get("state", "Down")

    if current_state == "Exchange" and ip2 in network1 and src_ip not in ips:
        lsr_layer = packet.getlayer(OSPF_LSReq)
        jumlah_lsreq = len(lsr_layer.requests)
        
        print(f"Received LSR from {src_ip}, moving to Loading state")
        tracking_state[interface]["state"] = "Loading"

        for lsr in lsr_layer.requests:
            lsreqdb_list.append(lsr)

        send_ospf_lsu(interface, src_broadcast, source_ip, src_ip)

def handle_lsu_packet(packet, interface, src_broadcast, source_ip, ospfhdr_layer):
    """Handle OSPF Link State Update packets"""
    global lsackdb_list, jumlah_lsulsa, penghitung, lsanew, seq_global, totallink
    
    src_ip = packet[IP].src
    ip2 = ipaddress.IPv4Address(src_ip)
    ip1 = tracking_state.get(interface, {}).get("ip_address")
    netmask1 = tracking_state.get(interface, {}).get("netmask")
    
    if not ip1 or not netmask1:
        return
        
    network1 = ipaddress.IPv4Network(f"{ip1}/{netmask1}", strict=False)
    current_state = tracking_state.get(interface, {}).get("state", "Down")

    if current_state in ["Loading", "Exchange"] and ip2 in network1 and src_ip not in ips:
        lsu_layer = packet.getlayer(OSPF_LSUpd)
        jumlah_lsulsa = lsu_layer.lsacount
        
        print(f"Received LSU from {src_ip}, moving to Full state")
        tracking_state[interface]["state"] = "Full"

        for lsalsu in lsu_layer.lsalist:
            lsackdb_list.append(lsalsu)

        # Send our own LSU if this is the first time
        if penghitung == 0:
            ip_lsu2 = IP(src=src_broadcast, dst=broadcast_ip)
            ospf_hdr_lsu2 = OSPF_Hdr(version=2, type=4, src=source_ip, area=area_id)
            
            lsalist45 = [
                OSPF_Router_LSA(
                    age=3300,
                    options=0x02,
                    type=1,
                    id="192.168.1.2",
                    adrouter="192.168.1.2",
                    seq=seq_global,
                    linkcount=totallink,
                    linklist=[
                        OSPF_Link(id="10.10.1.2", data="10.10.1.2", type=2, metric=1),
                        OSPF_Link(id="192.168.1.0", data="255.255.255.0", type=3, metric=1)
                    ]
                ),
                OSPF_Network_LSA(
                    age=3300,
                    options=option_default,
                    type=2,
                    id="10.10.1.2",
                    adrouter="192.168.1.2",
                    seq=0x80000123,
                    mask="255.255.255.0",
                    routerlist=["10.10.1.1", "192.168.1.2"]
                )
            ]

            lsanew = lsackdb_list + lsalist45
            
            ospf_lsu_pkt45 = (
                ip_lsu2 /
                ospf_hdr_lsu2 /
                OSPF_LSUpd(
                    lsacount=len(lsanew),
                    lsalist=lsanew
                )
            )
            send(ospf_lsu_pkt45, iface=interface, verbose=0)
            penghitung += 1

        send_ospf_lsaack(interface, src_broadcast, source_ip, broadcast_ip)

def sniff_packets(interface, src_broadcast, source_ip):
    """Sniff incoming OSPF packets"""
    print(f"Sniffing packets on interface {interface}...")
    sniff(
        iface=interface,
        filter="ip proto ospf",
        prn=lambda pkt: handle_incoming_packet(pkt, interface, src_broadcast, source_ip),
        store=False,
        timeout=100000000
    )

if __name__ == "__main__":
    threads = []
    interfaces_info = get_interfaces_info_with_interface_name()

    for info in interfaces_info:
        iplist = ipaddress.IPv4Address(info['ip_address'])

        if target_ip < iplist:
            target_ip = iplist
            source_ip = str(target_ip)
        elif target_ip == iplist:
            continue
        elif target_ip > iplist:
            source_ip = str(target_ip)

        # Skip ens4 interface
        if info['interface'] != 'ens4':
            tracking_state[info['interface']] = {
                "state": "Down",
                "ip_address": info['ip_address'],
                "netmask": info['netmask'],
            }

            # Start Hello thread
            hello_thread = threading.Thread(
                target=send_hello_periodically,
                args=(10, info['interface'], info['ip_address'], source_ip)
            )
            hello_thread.daemon = True
            hello_thread.start()
            threads.append(hello_thread)

            # Start packet sniffing thread
            recv_thread = threading.Thread(
                target=sniff_packets,
                args=(info['interface'], info['ip_address'], source_ip)
            )
            recv_thread.daemon = True
            recv_thread.start()
            threads.append(recv_thread)

    print(f"Threads: {len(threads)}")
    print(f"Neighbor states: {tracking_state}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Program terminated by user.")