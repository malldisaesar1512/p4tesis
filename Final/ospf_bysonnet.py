from asyncio import threads
from cmath import inf
from os import link
import os
from socket import timeout
from turtle import st
from scapy.all import *
from scapy.contrib.ospf import *
import time
import threading
import random
import psutil
import socket
import ipaddress
import argparse
from atexit import register
from operator import index
import sys
import struct
import subprocess
from datetime import datetime

#global variable
neighbor_state = "Down"
penghitung = 0
option_default = 0x02
default_age = 0  # Fresh LSA age
hello_interval = 10
dead_interval = 40
priority_default = 128
broadcast_ip = "224.0.0.5"
area_id = "0.0.0.0"
seq_base = 0x80000001  # Standard OSPF initial sequence number
seq_counter = 0
router_status = "Master"
id_dbd = ''

# Use consistent Router ID
router_id = "10.10.1.2"  # Main Router ID - keep consistent
backup_default = "0.0.0.0"
neighbor_default = "10.10.2.1"
dr = "10.10.1.2"
bdr = "10.10.1.1"

# Database lists
lsadb_list = []
lsreq_list = []
lsreqdb_list = []
lsudb_list = []
lsack_list = []
lsackdb_list = []
lsulist = None
a = []
b = []
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
source_ip = ""

ospf_link_list = []
lsadb_hdr_default = []
seq_exchange = 0

# Fixed default links - ensure proper format
lsadb_link_default = [
    OSPF_Link(id="10.10.1.0", data="255.255.255.0", type=3, metric=1), 
    OSPF_Link(id="192.168.1.0", data="255.255.255.0", type=3, metric=1)
]

#Membuat paket Ethernet
eth = Ether()

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

# Fixed LSA types with proper sequence numbers
def get_next_sequence():
    global seq_counter
    seq_counter += 1
    return seq_base + seq_counter

def create_router_lsa():
    """Create properly formatted Router LSA"""
    return OSPF_Router_LSA(
        age=default_age,
        options=option_default,
        type=1,
        id=router_id,
        adrouter=router_id,  # Must match ID
        seq=get_next_sequence(),
        linkcount=len(ospf_link_list),
        linklist=ospf_link_list
    )

def create_network_lsa(network_ip, mask, router_list):
    """Create properly formatted Network LSA"""
    return OSPF_Network_LSA(
        age=default_age,
        options=option_default,
        type=2,
        id=network_ip,
        adrouter=router_id,
        seq=get_next_sequence(),
        mask=mask,
        routerlist=router_list
    )

#################### P4 CONTROLLER #####################
def read_registerAll(register, thrift_port):
    p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(input="register_read %s" % (register))
    reg_val = [l for l in stdout.split('\n') if ' %s' % (register) in l][0].split('= ', 1)[1]
    return reg_val.split(", ")

def read_register(register, idx, thrift_port):
    p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(input="register_read %s %d" % (register, idx))
    reg_val = [l for l in stdout.split('\n') if ' %s[%d]' % (register, idx) in l][0].split('= ', 1)[1]
    return int(reg_val)

def write_register(register, idx, value, thrift_port):
    p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    command = "register_write %s %d %d" % (register, idx, value)
    stdout, stderr = p.communicate(input=command.encode('utf-8'))
    if stderr:
        print("Error:", stderr.decode('utf-8'))
    return

def table_delete(table, idx, thrift_port):
    p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(input="table_delete %s %d" % (table, idx))
    return 

def table_add(parametro, thrift_port):
    p = subprocess.Popen(
        ['simple_switch_CLI', '--thrift-port', str(thrift_port)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    command = f"table_add {parametro}\n"
    stdout, stderr = p.communicate(input=command)
    
    var_handle = [line for line in stdout.split('\n') if ' added' in line]
    
    if var_handle:
        handle_str = var_handle[0].split('handle ', 1)[1]
        return int(handle_str)
    else:
        raise RuntimeError(f"Failed to add table entry: {stderr}")

def table_entry(table, network, thrift_port):
    p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(input="table_dump_entry_from_key %s %s" % (table, network))
    entry_val = [l for l in stdout.split('\n') if ' %s' % ('Dumping') in l][0].split('0x', 1)[1]
    return int(entry_val)
#################### P4 CONTROLLER #####################

def get_interfaces_info_with_interface_name():
    global list_ip, networklist
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    interfaces = []
    list_ip = []
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
                    
                    if network_pre in networklist and ip in list_ip:
                        continue
                    else:
                        networklist.append(network_pre)
                        list_ip.append(ip)
                    
                    interface_info = {
                        "interface": iface,
                        "ip_address": ip,
                        "netmask": netmask,
                        "network": network_address,
                        "status": "up" if is_up else "down",
                        "sequence": get_next_sequence()
                    }
                    interfaces.append(interface_info)
                    h += 1

    return interfaces

def build_ospf_links():
    """Build OSPF link list from interfaces"""
    global ospf_link_list, lsadb_hdr_default
    
    interfaces_info = get_interfaces_info_with_interface_name()
    ospf_link_list.clear()
    lsadb_hdr_default.clear()
    
    for info in interfaces_info:
        # Add stub network links (Type 3)
        if info["interface"] != "lo":  # Skip loopback
            link = OSPF_Link(
                id=info['network'], 
                data=info['netmask'], 
                type=3,  # Stub network
                metric=1
            )
            ospf_link_list.append(link)
            
            # Create LSA header for this router
            lsa_hdr = OSPF_LSA_Hdr(
                age=default_age,
                options=option_default,
                type=1,
                id=router_id,
                adrouter=router_id,
                seq=info['sequence']
            )
            if lsa_hdr not in lsadb_hdr_default:
                lsadb_hdr_default.append(lsa_hdr)

def send_hello_periodically(interval, interface, ip_address, source_ip):
    """Kirim paket Hello OSPF secara berkala"""
    global neighbor_state, tracking_state, ospf_link_list, lsadb_hdr_default
    
    while True:
        # Rebuild links periodically
        build_ospf_links()
        
        if tracking_state.get(interface, {}).get("state", "Down") == "Down":
            ip_broadcast_hello = IP(src=ip_address, dst=broadcast_ip)
            ospf_header = OSPF_Hdr(version=2, type=1, src=source_ip, area=area_id)
            
            hello_packet = OSPF_Hello(
                mask="255.255.255.0",
                hellointerval=hello_interval,
                options=option_default,  
                prio=priority_default,
                deadinterval=dead_interval,
                router=source_ip,  # Use consistent source IP
                backup=backup_default,
                neighbors=[]
            )
            
            ospf_packet_hello = eth / ip_broadcast_hello / ospf_header / hello_packet
            sendp(ospf_packet_hello, iface=interface, verbose=0)
        
        print(f"[{time.strftime('%H:%M:%S')}] Interface {interface} - State: {tracking_state.get(interface, {}).get('state', 'Down')}")
        print(f"OSPF Links: {len(ospf_link_list)} links")
        print(f"Tracking State: {tracking_state}")
        
        time.sleep(interval)

def send_ospf_dbd_first(interface, src_broadcast, source_ip, neighbor_ip, seq_num):
    """Send initial Database Description packet"""
    ip_dbd = IP(src=src_broadcast, dst=str(neighbor_ip))
    ospf_hdr_dbd = OSPF_Hdr(version=2, type=2, src=source_ip, area=area_id)
    
    ospf_dbd_pkt = (
        eth /
        ip_dbd /
        ospf_hdr_dbd /
        OSPF_DBDesc(
            options=option_default,
            mtu=1500,
            dbdescr=0x07,  # I+M+MS bits
            ddseq=seq_num,
            lsaheaders=[]
        )
    )
    
    print(f"[{time.strftime('%H:%M:%S')}] Sending initial DBD to {neighbor_ip} - Seq: {seq_num}")
    sendp(ospf_dbd_pkt, iface=interface, verbose=0)

def send_ospf_dbd(interface, src_broadcast, source_ip, neighbor_router_ip):
    """Send Database Description packet with LSA headers"""
    global seq_exchange
    
    ip_dbd = IP(src=src_broadcast, dst=str(neighbor_router_ip))
    ospf_hdr_dbd = OSPF_Hdr(version=2, type=2, src=source_ip, area=area_id)
    
    seq_num = seq_exchange + 1 if seq_exchange else get_next_sequence()
    
    # Create fresh LSA headers
    build_ospf_links()
    current_lsa_headers = []
    
    # Add Router LSA header
    router_lsa_hdr = OSPF_LSA_Hdr(
        age=default_age,
        options=option_default,
        type=1,
        id=router_id,
        adrouter=router_id,
        seq=get_next_sequence()
    )
    current_lsa_headers.append(router_lsa_hdr)
    
    ospf_dbd_pkt = (
        eth /
        ip_dbd /
        ospf_hdr_dbd /
        OSPF_DBDesc(
            options=option_default,
            mtu=1500,
            dbdescr=0x01,  # MS bit only
            ddseq=seq_num,
            lsaheaders=current_lsa_headers
        )
    )
    
    print(f"[{time.strftime('%H:%M:%S')}] Sending DBD to {neighbor_router_ip} - Seq: {seq_num}, LSAs: {len(current_lsa_headers)}")
    sendp(ospf_dbd_pkt, iface=interface, verbose=0)

def send_ospf_lsr(interface, src_broadcast, source_ip, neighbor_ip):
    """Send Link State Request"""
    global lsreq_list, lsadb_list
    
    ip_lsr = IP(src=src_broadcast, dst=str(neighbor_ip))
    ospf_hdr_lsr = OSPF_Hdr(version=2, type=3, src=source_ip, area=area_id)
    
    lsreq_list.clear()
    current_interfaces = [info['ip_address'] for info in get_interfaces_info_with_interface_name()]
    
    for lsa in lsadb_list:
        lsa_id = lsa.id
        lsa_adrouter = lsa.adrouter
        lsa_type = lsa.type
        
        # Convert type if needed
        if lsa_type == 'router':
            lsa_type = 1
        elif lsa_type == 'network':
            lsa_type = 2
        
        # Only request LSAs from other routers
        if lsa_adrouter not in current_interfaces:
            lsr_item = OSPF_LSReq_Item(
                type=lsa_type,
                id=lsa_id,
                adrouter=lsa_adrouter
            )
            lsreq_list.append(lsr_item)
    
    if lsreq_list:
        ospf_lsr_pkt = (
            eth /
            ip_lsr /
            ospf_hdr_lsr /
            OSPF_LSReq(requests=lsreq_list)
        )
        
        print(f"[{time.strftime('%H:%M:%S')}] Sending LSR to {neighbor_ip} - Requests: {len(lsreq_list)}")
        sendp(ospf_lsr_pkt, iface=interface, verbose=0)
    
    lsadb_list.clear()

def send_ospf_lsu(interface, src_broadcast, source_ip, neighbor_ip):
    """Send Link State Update"""
    global lsudb_list, lsreqdb_list
    
    ip_lsu = IP(src=src_broadcast, dst=str(neighbor_ip))
    ospf_hdr_lsu = OSPF_Hdr(version=2, type=4, src=source_ip, area=area_id)
    
    lsudb_list.clear()
    
    for lsr in lsreqdb_list:
        lsr_type = lsr.type
        lsr_id = lsr.id
        lsr_adrouter = lsr.adrouter
        
        if lsr_type in [1, 'router']:
            # Create Router LSA
            build_ospf_links()  # Ensure links are current
            router_lsa = OSPF_Router_LSA(
                age=default_age,
                options=option_default,
                type=1,
                id=router_id,
                adrouter=router_id,
                seq=get_next_sequence(),
                linkcount=len(ospf_link_list),
                linklist=ospf_link_list
            )
            lsudb_list.append(router_lsa)
            
        elif lsr_type in [2, 'network']:
            # Create Network LSA
            network_lsa = OSPF_Network_LSA(
                age=default_age,
                options=option_default,
                type=2,
                id=lsr_id,
                adrouter=router_id,
                seq=get_next_sequence(),
                mask="255.255.255.0",
                routerlist=[router_id, lsr_adrouter]
            )
            lsudb_list.append(network_lsa)
    
    if lsudb_list:
        ospf_lsu_pkt = (
            eth /
            ip_lsu /
            ospf_hdr_lsu /
            OSPF_LSUpd(
                lsacount=len(lsudb_list),
                lsalist=lsudb_list
            )
        )
        
        print(f"[{time.strftime('%H:%M:%S')}] Sending LSU to {neighbor_ip} - LSAs: {len(lsudb_list)}")
        sendp(ospf_lsu_pkt, iface=interface, verbose=0)
    
    lsreqdb_list.clear()

def send_ospf_lsaack(interface, src_broadcast, source_ip, broadcast_ip_dst):
    """Send LSA Acknowledgment"""
    global lsackdb_list, lsack_list, db_lsap4, newrute
    
    ip_lsack = IP(src=src_broadcast, dst=str(broadcast_ip_dst))
    ospf_hdr_lsack = OSPF_Hdr(version=2, type=5, src=source_ip, area=area_id)
    
    lsack_list.clear()
    newrute.clear()
    
    for lsa in lsackdb_list:
        # Create ACK header
        lsa_ack_hdr = OSPF_LSA_Hdr(
            age=default_age,
            options=option_default,
            type=lsa.type,
            id=lsa.id,
            adrouter=lsa.adrouter,
            seq=lsa.seq
        )
        lsack_list.append(lsa_ack_hdr)
        
        # Process Network LSA for routing
        if hasattr(lsa, 'routerlist') and hasattr(lsa, 'mask'):
            for router_ip in lsa.routerlist:
                if router_ip != router_id:  # Don't add routes to self
                    try:
                        network = ipaddress.IPv4Network(f"{router_ip}/{lsa.mask}", strict=False)
                        route_entry = f"{network.network_address}/{network.prefixlen}"
                        if route_entry not in newrute:
                            newrute.append(route_entry)
                            print(f"[ROUTE] Learned: {route_entry} via {interface}")
                    except Exception as e:
                        print(f"[ERROR] Failed to process route {router_ip}/{lsa.mask}: {e}")
    
    if lsack_list:
        ospf_lsack_pkt = (
            eth /
            ip_lsack /
            ospf_hdr_lsack /
            OSPF_LSAck(lsaheaders=lsack_list)
        )
        
        print(f"[{time.strftime('%H:%M:%S')}] Sending LSAck to {broadcast_ip_dst} - ACKs: {len(lsack_list)}")
        sendp(ospf_lsack_pkt, iface=interface, verbose=0)
    
    lsackdb_list.clear()

def handle_incoming_packet(packet, interface, src_broadcast, source_ip):
    """Handle incoming OSPF packets"""
    global tracking_state, seq_exchange, lsadb_list, lsreqdb_list, lsackdb_list, penghitung
    
    if not packet.haslayer(OSPF_Hdr):
        return
    
    ospf_hdr = packet[OSPF_Hdr]
    src_ip = packet[IP].src
    
    print(f"[{time.strftime('%H:%M:%S')}] RX: {ospf_hdr.summary()} from {src_ip}")
    
    # Validate source IP is in same network
    try:
        ip_src = ipaddress.IPv4Address(src_ip)  
        local_ip = tracking_state.get(interface, {}).get("ip_address")
        local_netmask = tracking_state.get(interface, {}).get("netmask")
        
        if not local_ip or not local_netmask:
            return
            
        local_network = ipaddress.IPv4Network(f"{local_ip}/{local_netmask}", strict=False)
        
        if ip_src not in local_network or src_ip in list_ip:
            return
            
    except Exception as e:
        print(f"[ERROR] Network validation failed: {e}")
        return
    
    current_state = tracking_state.get(interface, {}).get("state", "Down")
    neighbor_router_id = ospf_hdr.src
    
    if ospf_hdr.type == 1:  # Hello packet
        if current_state == "Down":
            print(f"[STATE] {interface}: Down -> Init (Hello from {src_ip})")
            tracking_state[interface]["state"] = "Init"
            
            # Send Hello response
            hello_response = create_hello_response(src_broadcast, neighbor_router_id)
            send_hello_response(interface, hello_response)
            
        elif current_state == "Init":
            print(f"[STATE] {interface}: Init -> 2-Way (Hello with neighbor list)")
            tracking_state[interface]["state"] = "2-Way"
            
            # Send Hello and initiate DBD
            hello_response = create_hello_response(src_broadcast, neighbor_router_id)
            send_hello_response(interface, hello_response)
            send_ospf_dbd_first(interface, src_broadcast, source_ip, src_ip, get_next_sequence())
            
        elif current_state in ["2-Way", "Full"]:
            # Maintain adjacency
            hello_response = create_hello_response(src_broadcast, neighbor_router_id)
            send_hello_response(interface, hello_response)
    
    elif ospf_hdr.type == 2:  # DBD packet
        if current_state == "2-Way":
            dbd_layer = packet.getlayer(OSPF_DBDesc)
            if dbd_layer and dbd_layer.dbdescr == 0x00:  # Slave packet
                print(f"[STATE] {interface}: 2-Way -> Exchange (Master)")
                tracking_state[interface]["state"] = "Exchange" 
                seq_exchange = dbd_layer.ddseq
                
                # Process LSA headers
                lsadb_list.extend(dbd_layer.lsaheaders)
                print(f"[DBD] Received {len(dbd_layer.lsaheaders)} LSA headers")
                
                send_ospf_dbd(interface, src_broadcast, source_ip, src_ip)
                send_ospf_lsr(interface, src_broadcast, source_ip, src_ip)
    
    elif ospf_hdr.type == 3:  # LSR packet
        if current_state == "Exchange":
            print(f"[STATE] {interface}: Exchange -> Loading")
            tracking_state[interface]["state"] = "Loading"
            
            lsr_layer = packet.getlayer(OSPF_LSReq)
            if lsr_layer:
                lsreqdb_list.extend(lsr_layer.requests)
                print(f"[LSR] Received {len(lsr_layer.requests)} LSA requests")
                send_ospf_lsu(interface, src_broadcast, source_ip, src_ip)
    
    elif ospf_hdr.type == 4:  # LSU packet
        if current_state in ["Loading", "Exchange", "Full"]:
            if current_state == "Loading":
                print(f"[STATE] {interface}: Loading -> Full")
                tracking_state[interface]["state"] = "Full"
            
            lsu_layer = packet.getlayer(OSPF_LSUpd)
            if lsu_layer:
                lsackdb_list.extend(lsu_layer.lsalist)
                print(f"[LSU] Received {len(lsu_layer.lsalist)} LSAs")
                
                # Send our own LSAs if first time reaching Full
                if penghitung == 0 and current_state != "Full":
                    send_own_lsa_update(interface, src_broadcast, source_ip)
                    penghitung += 1
                
                send_ospf_lsaack(interface, src_broadcast, source_ip, broadcast_ip)

def create_hello_response(src_ip, neighbor_id):
    """Create Hello response packet"""
    return OSPF_Hello(
        mask="255.255.255.0",
        hellointerval=hello_interval,
        options=option_default,
        prio=priority_default,
        deadinterval=dead_interval,
        router=router_id,
        backup=backup_default,
        neighbors=[neighbor_id] if neighbor_id else []
    )

def send_hello_response(interface, hello_packet):
    """Send Hello response"""
    ip_hello = IP(src=tracking_state[interface]["ip_address"], dst=broadcast_ip)
    ospf_hdr = OSPF_Hdr(version=2, type=1, src=source_ip, area=area_id)
    
    full_packet = eth / ip_hello / ospf_hdr / hello_packet
    sendp(full_packet, iface=interface, verbose=0)

def send_own_lsa_update(interface, src_broadcast, source_ip):
    """Send our own LSA update"""
    build_ospf_links()
    
    # Create Router LSA
    router_lsa = create_router_lsa()
    
    # Create Network LSA if we're DR
    network_lsa = create_network_lsa(
        network_ip=dr,
        mask="255.255.255.0", 
        router_list=[router_id]
    )
    
    lsa_list = [router_lsa, network_lsa]
    
    ip_lsu = IP(src=src_broadcast, dst=broadcast_ip)
    ospf_hdr = OSPF_Hdr(version=2, type=4, src=source_ip, area=area_id)
    
    lsu_packet = (
        eth /
        ip_lsu /
        ospf_hdr /
        OSPF_LSUpd(
            lsacount=len(lsa_list),
            lsalist=lsa_list
        )
    )
    
    print(f"[{time.strftime('%H:%M:%S')}] Sending own LSA update - {len(lsa_list)} LSAs")
    sendp(lsu_packet, iface=interface, verbose=0)

def sniff_packets(interface, src_broadcast, source_ip):
    """Sniff and process OSPF packets"""
    print(f"[INFO] Starting packet capture on {interface}")
    sniff(
        iface=interface,
        filter="ip proto ospf",
        prn=lambda pkt: handle_incoming_packet(pkt, interface, src_broadcast, source_ip),
        store=False,
        timeout=None
    )

if __name__ == "__main__":
    print("=" * 60)
    print("OSPF Router Implementation - Fixed Version")
    print("=" * 60)
    
    threads = []
    interfaces_info = get_interfaces_info_with_interface_name()
    
    # Determine source IP (highest IP)
    for info in interfaces_info:
        current_ip = ipaddress.IPv4Address(info['ip_address'])
        if target_ip < current_ip:
            target_ip = current_ip
            source_ip = str(target_ip)
    
    print(f"[CONFIG] Router ID: {router_id}")
    print(f"[CONFIG] Source IP: {source_ip}")
    print(f"[CONFIG] Area: {area_id}")
    
    # Initialize interfaces (skip loopback and management)
    for info in interfaces_info:
        if info['interface'] in ['lo', 'ens4']:  # Skip loopback and management
            continue
            
        interface_name = info['interface']
        interface_ip = info['ip_address']
        
        # Initialize tracking state
        tracking_state[interface_name] = {
            "state": "Down",
            "ip_address": interface_ip,
            "netmask": info['netmask']
        }
        
        print(f"[INIT] Interface {interface_name}: {interface_ip}")
        
        # Start Hello sender thread
        hello_thread = threading.Thread(
            target=send_hello_periodically,
            args=(hello_interval, interface_name, interface_ip, source_ip),
            daemon=True
        )
        hello_thread.start()
        threads.append(hello_thread)
        
        # Start packet receiver thread  
        recv_thread = threading.Thread(
            target=sniff_packets,
            args=(interface_name, interface_ip, source_ip),
            daemon=True
        )
        recv_thread.start()
        threads.append(recv_thread)
    
    print(f"[INFO] Started {len(threads)} threads for {len(tracking_state)} interfaces")
    print("[INFO] OSPF Router is running. Press Ctrl+C to stop.")