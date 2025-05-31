#!/usr/bin/env python3

import os
import sys
import time
import socket
import struct
import random
import psutil
import threading
import ipaddress
import subprocess
from datetime import datetime

# Check if running as root
if os.geteuid() != 0:
    print("This script must be run as root. Please use sudo.")
    sys.exit(1)

try:
    from scapy.all import (
        Ether, IP, sendp, sniff,
        load_contrib
    )
    load_contrib("ospf")
    from scapy.contrib.ospf import (
        OSPF_Hdr, OSPF_Hello, OSPF_DBDesc,
        OSPF_LSReq, OSPF_LSUpd, OSPF_LSAck,
        OSPF_Router_LSA, OSPF_Network_LSA,
        OSPF_Link, OSPF_LSA_Hdr, OSPF_LSReq_Item
    )
    from scapy.layers.l2 import Ether
except ImportError as e:
    print(f"Error importing Scapy: {e}")
    print("Please install required packages by running:")
    print("sudo bash install_dependencies.sh")
    sys.exit(1)

# Disable Scapy warnings
conf.verb = 0

# Check if running as root
if os.geteuid() != 0:
    print("This script must be run as root. Please use sudo.")
    sys.exit(1)

# Scapy imports
try:
    from scapy.all import (
        Ether, IP, sendp, sniff,
        load_contrib
    )
    load_contrib("ospf")
    from scapy.contrib.ospf import (
        OSPF_Hdr, OSPF_Hello, OSPF_DBDesc,
        OSPF_LSReq, OSPF_LSUpd, OSPF_LSAck,
        OSPF_Router_LSA, OSPF_Network_LSA,
        OSPF_Link, OSPF_LSA_Hdr, OSPF_LSReq_Item
    )
    from scapy.layers.l2 import Ether
except ImportError as e:
    print(f"Error importing Scapy: {e}")
    print("Please install required packages:")
    print("sudo apt-get update")
    print("sudo apt-get install python3-scapy python3-psutil")
    sys.exit(1)

# Disable Scapy warnings
conf.verb = 0
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

# Constants for OSPF packet types and multicast addresses
OSPF_TYPE_HELLO = 1
OSPF_TYPE_DBD = 2
OSPF_TYPE_LSR = 3
OSPF_TYPE_LSU = 4
OSPF_TYPE_LSACK = 5

# OSPF packet field constants (MikroTik compatible)
OSPF_OPTIONS_E = 0x02     # External Routing capability (E-bit)
OSPF_OPTIONS_N = 0x08     # N-bit for NSSA
OSPF_OPTIONS_DC = 0x04    # Demand Circuits
OSPF_HELLO_INTERVAL = 10  # MikroTik default hello interval
OSPF_DEAD_INTERVAL = 40   # MikroTik default dead interval
OSPF_PRIORITY = 1         # Normal router priority
OSPF_MTU = 1500          # Standard MTU size
OSPF_AUTH_TYPE = 0       # No authentication
OSPF_AUTH_DATA = b"\x00" * 8  # Empty auth data

# OSPF multicast addresses and areas
OSPF_ALL_SPF_ROUTERS = "224.0.0.5"     # All OSPF routers multicast
OSPF_ALL_DR_ROUTERS = "224.0.0.6"       # All DR/BDR routers multicast
OSPF_AREA_BACKBONE = "0.0.0.0"          # Backbone area

# OSPF Constants for MikroTik Compatibility
broadcast_ip = OSPF_ALL_SPF_ROUTERS     # Default multicast address
area_id = OSPF_AREA_BACKBONE            # Default area
router_id = "10.10.1.2"                 # Router ID
router_id2 = "192.168.1.2"              # Router ID 2 (Neighbor)
dr = "10.10.1.2"                        # Designated Router
bdr = "10.10.1.1"                       # Backup Designated Router

# State variables
target_ip = ipaddress.IPv4Address("0.0.0.0")
neighbor_state = "Down"
penghitung = 0                          # Counter for LSU packets
seq_global = 0x80000001                 # Global sequence number
seq_random = random.randint(0x80000001, 0x8000000F)  # Initial sequence number
seq_exchange = 0                        # Exchange sequence number

# Lists and dictionaries for OSPF operation
lsadb_list = []                         # LSA database
lsreq_list = []                         # LS request list
lsreqdb_list = []                       # LS request database
lsudb_list = []                         # LSU database
lsack_list = []                         # LSAck list
lsackdb_list = []                       # LSAck database
newrute = []                           # New routes
rutep4 = []                            # P4 routes
tracking_state = {}                     # Interface state tracking
db_lsap4 = {}                          # P4 LSA database

# Global state variables with MikroTik compatible defaults
neighbor_state = "Down"
option_default = OSPF_OPTIONS_E  # Use only E-bit for MikroTik compatibility
default_age = 1           # Fresh LSA age
hello_interval = OSPF_HELLO_INTERVAL
dead_interval = OSPF_DEAD_INTERVAL
priority_default = OSPF_PRIORITY
penghitung = 0           # Counter for LSU packets
seq_global = 0x80000001  # Initial sequence number (must start at 0x80000001)
seq_random = random.randint(0x80000001, 0x8000000F)  # Random initial sequence
seq_exchange = 0         # Exchange sequence number

# Initialize default timers
DefaultHelloTimer = hello_interval
DefaultDeadTimer = dead_interval
DefaultWaitTimer = dead_interval
DefaultExStartTimer = 10  # Seconds to wait in ExStart state

# OSPF protocol thresholds
MaxAgeDiff = 900         # Maximum age difference for accepting LSAs
MinLSArrival = 1000     # Minimum arrival time between LSAs (ms)
MaxLSAGenDelay = 5      # Maximum delay for LSA generation (seconds)

# OSPF multicast addresses and areas
OSPF_ALL_SPF_ROUTERS = "224.0.0.5"     # All OSPF routers multicast
OSPF_ALL_DR_ROUTERS = "224.0.0.6"       # All DR/BDR routers multicast
OSPF_AREA_BACKBONE = "0.0.0.0"          # Backbone area

# OSPF Constants for MikroTik Compatibility
broadcast_ip = OSPF_ALL_SPF_ROUTERS     # Default multicast address
area_id = OSPF_AREA_BACKBONE            # Default area
router_id = "10.10.1.2"                 # Router ID
router_id2 = "192.168.1.2"              # Router ID 2 (Neighbor)
dr = "10.10.1.2"                        # Designated Router
bdr = "10.10.1.1"                       # Backup Designated Router

# State variables
target_ip = ipaddress.IPv4Address("0.0.0.0")
neighbor_state = "Down"
penghitung = 0                          # Counter for LSU packets
seq_global = 0x80000001                 # Global sequence number
seq_random = random.randint(0x80000001, 0x8000000F)  # Initial sequence number
seq_exchange = 0                        # Exchange sequence number

# Lists and dictionaries for OSPF operation
lsadb_list = []                         # LSA database
lsreq_list = []                         # LS request list
lsreqdb_list = []                       # LS request database
lsudb_list = []                         # LSU database
lsack_list = []                         # LSAck list
lsackdb_list = []                       # LSAck database
newrute = []                           # New routes
rutep4 = []                            # P4 routes
tracking_state = {}                     # Interface state tracking
db_lsap4 = {}                          # P4 LSA database

# Global state
neighbor_state = "Down"
option_default = OSPF_OPTIONS_E  # Use only E-bit for MikroTik compatibility
default_age = 1           # Fresh LSA age
hello_interval = OSPF_HELLO_INTERVAL
dead_interval = OSPF_DEAD_INTERVAL
priority_default = OSPF_PRIORITY
penghitung = 0           # Counter for LSU packets
seq_global = 0x80000001  # Initial sequence number (must start at 0x80000001)
seq_random = random.randint(0x80000001, 0x8000000F)  # Random initial sequence
seq_exchange = 0         # Exchange sequence number
router_status = "Master"
id_dbd = ''
router_id = "10.10.1.2"  # Router ID
router_id2 = "192.168.1.2"  # Router ID 2 (Neighbor)
# area_id = "0.0.0.0"        # Area ID
# interface = "ens5"         # Network interface
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
lsulist = None
a = []
b = []
lsacknih = []
LSA_listdb = []
newrute = []
rutep4 = []
# interface = []
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

lsadb_link_default = [OSPF_Link(id = "10.10.1.0", data = "10.10.1.0", type = 3, metric = 1), 
                OSPF_Link(id = "192.168.1.0", data = "192.168.1.0", type = 3, metric = 1)]

#Membuat paket Ethernet
eth = Ether()

ip_broadcast = IP(src=router_id, dst="224.0.0.5")

ospf_hello_first = OSPF_Hello(
    mask="255.255.255.0",
    hellointerval=OSPF_HELLO_INTERVAL,  # MikroTik default
    options=OSPF_OPTIONS_E,             # External routing capability only
    prio=OSPF_PRIORITY,                # Normal priority
    deadinterval=OSPF_DEAD_INTERVAL,    # MikroTik default
    router=router_id,
    backup="0.0.0.0",
    neighbors=[]      # Will be populated during neighbor discovery
          # Empty auth data
)


#TYPE OF LSA_PACKET
lsa_type1 = OSPF_Router_LSA(
            age = 3300, # Age of the LSA
            options=0x02, # Options field
            type=1,  # Router LSA
            id="10.10.1.2", # LSA ID
            adrouter="10.10.1.2", # Advertising router
            seq=0x80000123,  # Sequence number
            linkcount=2, # Number of links
            linklist=[] # List of links
        )
lsa_type2 = OSPF_Network_LSA(
            age = 3300, # Age of the LSA
            options=option_default, # Options field
            type=2,  # Network LSA
            id="10.10.1.2", # LSA ID
            adrouter="10.10.1.2", # Advertising router
            seq=0x80000124,  # Sequence number
            mask="255.255.255.0", # Subnet mask
            routerlist=[] # List of routers
        )
lsarouter_default = OSPF_LSA_Hdr(
                age = 3300,
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

# def table_add(table, parametro, thrift_port):
#     p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
#     stdout, stderr = p.communicate(input="table_add %s" % (parametro))
#     var_handle = [l for l in stdout.split('\n') if ' %s' % ('added') in l][0].split('handle ', 1)[1]
#     return int(var_handle)
# import subprocess

def table_add(parametro, thrift_port):
    p = subprocess.Popen(
        ['simple_switch_CLI', '--thrift-port', str(thrift_port)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True  # Penting agar input/output berupa string
    )
    
    command = f"table_add {parametro}\n"
    stdout, stderr = p.communicate(input=command)
    
    # Cari baris yang mengandung kata 'added' untuk mengambil handle
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
    global ips, netmasks, networks, statuses, interfaces_info, networklist
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    interfaces = []  # List untuk menyimpan data setiap interface sebagai dictionary
    ips = []         # List untuk menyimpan IP address
    networklist = []  # List untuk menyimpan network address
    h = 0
    for iface, addr_list in addrs.items():
        is_up = stats[iface].isup if iface in stats else False
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ip = addr.address
                netmask = addr.netmask
                if ip and netmask and ip != "127.0.0.1" and ip != "10.0.137.55":
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
                    h=h+1

    return interfaces


def send_hello_periodically(interval, interface, ip_address, source_ip):
    """Kirim paket Hello OSPF secara berkala"""
    global neighbor_state, neighbor_default, interfaces, ips, netmasks, networks, statuses, lsadb_link_default, lsadb_hdr_default, interfaces_info, totallink, seq_global,e
    while True:
        interfaces_info = get_interfaces_info_with_interface_name()
        
        # Format MikroTik-compatible OSPF packets
        if neighbor_state == "Down":
            # TTL=1 for local multicast as expected by MikroTik
            ip_broadcast_hello = IP(src=ip_address, dst=broadcast_ip, ttl=1)
            
            # MikroTik expects specific auth type (0 for none)
            ospf_header = OSPF_Hdr(
                version=2,
                type=1,  # Hello packet
                src=source_ip,
                area=area_id,
                authtype=0,  # No authentication
                authdata=b"\x00" * 8  # Empty auth data
            )
            
            ospf_hello_first.neighbors = []
            ospf_hello_first.router = ip_address
            # Create MikroTik compatible Hello packet
            ospf_hello_packet = eth / ip_broadcast_hello / ospf_header / ospf_hello_first
            # Send with proper checksums
            ospf_hello_packet = ospf_hello_packet.__class__(bytes(ospf_hello_packet))
            sendp(ospf_hello_packet, iface=interface, verbose=0)

        totallink = len(ospf_link_list)
        # print(f"thread: {threads}")
        print(f"neighbors_state: {tracking_state}")
        print(f"lisdbp4: {db_lsap4}")
        print(f"ospf_link_list: {ospf_link_list}")
        print(f"lsadb_hdr_default: {lsadb_hdr_default}")
        
        print(f"Sent OSPF Hello packet at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
        time.sleep(interval)

def send_ospf_dbd_first(interface, src_broadcast, source_ip, neighbor_ip, seq_num):
    """Send initial Database Description (DBD) packet with proper Master/Slave election flags"""
    ip_dbd = IP(src=src_broadcast, dst=str(neighbor_ip), ttl=1)  # TTL=1 for MikroTik
    ospf_hdr_dbd = OSPF_Hdr(
        version=2, 
        type=2,           # DBD packet
        src=source_ip, 
        area=area_id,
        authtype=OSPF_AUTH_TYPE
    )
    
    # Initial DBD flags:
    # I(Init) = 1, M(More) = 1, MS(Master/Slave) = 1
    # 0x07 = 0b0111 (I=1, M=1, MS=1)
    ospf_dbd_pkt1 = (
        eth /
        ip_dbd /
        ospf_hdr_dbd /
        OSPF_DBDesc(
            options=OSPF_OPTIONS_E,     # External routing capability
            mtu=OSPF_MTU,              # MTU size
            dbdescr=0x07,              # Init, More, and Master bits set
            ddseq=seq_num,            # Initial sequence number
            lsaheaders=[]              # No LSA headers in initial DBD
        )
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending DBD FIRST packet to {neighbor_ip} -  Seq: {seq_num}")
    sendp(ospf_dbd_pkt1, iface=interface, verbose=0)

def send_ospf_dbd(interface, src_broadcast, source_ip, neighbor_router_ip):
    """Kirim paket Database Description (DBD) lanjutan ke neighbor dengan flags dan seq_num yang benar"""
    ip_dbd = IP(src=src_broadcast, dst=str(neighbor_router_ip))
    ospf_hdr_dbd = OSPF_Hdr(version=2, type=2, src=source_ip, area=area_id)
    
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
        ) 
         
    )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending DBD packet to {neighbor_router_ip} - Flags: MS ({flag_value}), Seq: {seq_num}")
    sendp(ospf_dbd_pkt2, iface=interface, verbose=True)

def send_ospf_lsr(interface, src_broadcast, source_ip,neighbor_ip):
    global lsreq_list, lsadb_list, a
    """Kirim paket Link State Request (LSR) ke neighbor"""
    # Header IP unicast ke neighbor router IP
    ip_lsr = IP(src=src_broadcast, dst=str(neighbor_ip))
    
    # Header OSPF tipe 3: Link State Request Packet
    ospf_hdr_lsr = OSPF_Hdr(version=2, type=3, src=source_ip, area=area_id)

    for i in lsadb_list:
        # print(f"LSA {i}: {i.show()}") # Menampilkan informasi LSA
        id_lsa = i.id
        adrouter_lsa = i.adrouter
        type_lsa = i.type
        
        if type_lsa == 'router':
            type_lsa = 1
        elif type_lsa == 'network':
            type_lsa = 2

        if id_lsa in interfaces_info:
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

def send_ospf_lsu(interface, src_broadcast, source_ip, neighbor_ip):
    global lsudb_list, lsreqdb_list, lsa_type1, lsadb_link_default, jumlah_lsreq, b, lsulist
    """Send Link State Update (LSU) to neighbor with MikroTik compatible options"""
    # IP header with TTL=1 for local delivery
    ip_lsu = IP(src=src_broadcast, dst=str(neighbor_ip), ttl=1)
    
    # OSPF header with proper authentication fields
    ospf_hdr_lsu = OSPF_Hdr(
        version=2, 
        type=OSPF_TYPE_LSU,
        src=source_ip, 
        area=area_id,
        authtype=OSPF_AUTH_TYPE
    )

    for i in lsreqdb_list:
        type_lsr = i.type
        id_lsr = i.id
        adrouter_lsr = i.adrouter

        for info in interfaces_info:
                if info['ip_address'] == id_lsr:
                    seq_lsr = info['sequence']

        if type_lsr == 'router' or type_lsr == '1' or type_lsr == 1:
            lsulist = OSPF_Router_LSA(
                        age = 3300, # Age of the LSA
                        options=0x02, # Options field
                        type=type_lsr,  # Router LSA
                        id=id_lsr, # LSA ID
                        adrouter=adrouter_lsr, # Advertising router
                        seq=seq_lsr,  # Sequence number
                        linkcount=totallink, # Number of links
                        linklist=ospf_link_list # List of links
                    )
            
            lsudb_list.append(lsulist)

        elif type_lsr == 'network' or type_lsr == 2:
            lsulist = OSPF_Network_LSA(
                        age = 3300, # Age of the LSA
                        options=option_default, # Options field
                        type=2,  # Network LSA
                        id=id_lsr, # LSA ID
                        adrouter=adrouter_lsr, # Advertising router
                        seq=seq_lsr,  # Sequence number
                        mask="255.255.255.0", # Subnet mask
                        routerlist=ips # List of routers
                    )

            lsudb_list.append(lsulist)

    # print(f"LSU List: {lsudb_list}")
    
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

def send_ospf_lsaack(interface, src_broadcast, source_ip, broadcastip):
    global lsudb_list, lsack_list, lsackdb_list, lsarouter_default, lsacknih, newrute, lsanew, mac_src, networklist
    """Send Link State Acknowledgment with MikroTik compatible settings"""
    # IP header with TTL=1 for local delivery
    ip_lsack = IP(src=src_broadcast, dst=str(broadcastip), ttl=1)
    
    # OSPF header with proper authentication fields
    ospf_hdr_lsack = OSPF_Hdr(
        version=2,
        type=OSPF_TYPE_LSACK,
        src=source_ip,
        area=area_id,
        authtype=OSPF_AUTH_TYPE
    )
    
    # Buat LSU packet dengan LSAs yang diberikan

    for i in lsackdb_list:
        lsack_id = i.id
        lsack_adrouter = i.adrouter
        lsack_type = i.type
        lsack_seq = i.seq
        

        
        lsacknih = OSPF_LSA_Hdr(
                age = 3300,
                options=0x02,
                type=lsack_type,
                id=lsack_id,
                adrouter=lsack_adrouter,
                seq=lsack_seq
            )

        lsack_list.append(lsacknih)
    
        if lsack_type == 'network' or lsack_type == 2:
            lsdbp4 = i.routerlist
            netp4 = i.mask
            for i in lsdbp4:
                network5 = ipaddress.IPv4Network(f"{i}/{netp4}", strict=False)
                rute = f"{network5.network_address}/{network5.prefixlen}"
                print(f"Rute: {rute} - Netmask: {netp4} - Interface: {interface}")
                if rute not in newrute:  # Cek apakah rute sudah ada
                    newrute.append(rute)
                else:
                    continue
            db_lsap4[interface] = {"routelist": newrute, "netmask": netp4, "interface": interface, "ether_src": mac_src}

            
            # print(f"LSA {i}: {lsacknih}") # Menampilkan informasi LSA
    

    print(f"lsack.list: {lsack_list}")

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

    # for interface, data in db_lsap4.items():
    #     rutep4 = data["routelist"]
    #     macp4 = data["ether_src"]
    #     intp4 = data["interface"]
    #     if intp4 == "ens4":
    #         port_out = "0"
    #         table_name = "MyIngress.ipv4_lpm"
    #     elif intp4 == "ens5":
    #         port_out = "1"
    #         table_name = "MyIngress.ipv4_lpm2"

    #     for ip in rutep4:
    #         if ip in networklist:
    #             continue
    #         else:
    #             parametro = f"MyIngress.ipv4_lpm MyIngress.ipv4_forward {ip} => {macp4} {port_out}"
    #             try:
    #                 handle = table_add(parametro, 9090)
    #                 print(f"Added entry for {parametro} with handle {handle}")
    #             except Exception as e:
    #                 print(f"Error adding entry for {parametro}: {e}")

    lsackdb_list.clear()
    lsack_list.clear()
    lsanew.clear()

def handle_incoming_packet(packet, interface, src_broadcast, source_ip):
    """Fungsi untuk menangani paket yang diterima"""
    global neighbor_state, dbd_seq_num, seq_exchange, lsackdb_list, router_status, eth, ip_broadcast, ospf_header, ospf_hello_pkt, lsadb_list, jumlah_lsa, jumlah_lsreq, lsreq_list, lsreqdb_list, jumlah_lsulsa, lsudb_list, penghitung, lsanew, mac_src
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received packet on interface {interface}")
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
            ip2 = ipaddress.IPv4Address(src_ip)
            ip1 = tracking_state.get(interface, {}).get("ip_address")
            netmask1 = tracking_state.get(interface, {}).get("netmask")
            network1 = ipaddress.IPv4Network(f"{ip1}/{netmask1}", strict=False)
            src_neighbor = packet[OSPF_Hdr].src

            if tracking_state.get(interface, {}).get("state") == "Down":
                print(f"Received Hello from {src_ip}, moving to Init state")
                if ip2 in network1 and src_ip not in ips:
                    # print("Received Hello packet")
                    neighbor_state = "Full"
                    tracking_state[interface]["state"] = "Init"
                    print(tracking_state.get(interface, {}).get("state"))
                    neighbor_ip = src_neighbor
                    print(f"Received Hello from {src_ip}, moving to Init state or 2-Way")
                    ospf_hello_first.neighbors = [neighbor_ip]
                    ospf_hello_first.router = src_ip
                    ip_broadcast_hello = IP(src=src_broadcast, dst=broadcast_ip)
                    
                    ospf_packet_hello2 = eth / ip_broadcast_hello / ospf_header / ospf_hello_first
                    sendp(ospf_packet_hello2, iface=interface, verbose=0)
                    # print(f"{ospf_packet_hello2.show()}")
                    print(f"Sent OSPF Hello packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
            elif tracking_state.get(interface, {}).get("state") == "Init":
                if ip2 in network1 and src_ip not in ips:
                    # print("Received Hello packet")
                    tracking_state[interface]["state"] = "2-Way"
                    neighbor_ip = src_neighbor
                    print(f"Received Hello from {src_ip}, moving to 2-Way state")
                    # ospf_hello_first.backup = src_ip
                    ospf_hello_first.neighbors = [neighbor_ip]
                    ospf_hello_first.router = src_ip
                    ip_broadcast_hello = IP(src=src_broadcast, dst=broadcast_ip)

                    ospf_packet_hello2 = eth / ip_broadcast_hello / ospf_header / ospf_hello_first
                    sendp(ospf_packet_hello2, iface=interface, verbose=0)
                    send_ospf_dbd_first(interface, src_broadcast, source_ip, src_ip, seq_random)
                    # print(f"{ospf_packet_hello2.show()}")
                    print(f"Sent OSPF Hello packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
            elif tracking_state.get(interface, {}).get("state") == "Full":
                if ip2 in network1 and src_ip not in ips:
                    print("Received Hello packet on Full state")
                    tracking_state[interface]["state"] = "Full"
                    neighbor_ip = src_neighbor
                    ospf_hello_full = ospf_hello_first
                    ospf_hello_full.neighbors = [neighbor_ip]
                    ospf_hello_full.backup = [ospfhdr_layer.backup]
                    ospf_hello_full.router = [ospfhdr_layer.router]
                    ip_broadcast_hello = IP(src=src_broadcast, dst=broadcast_ip)
                    
                    # ospf_hello_first.backup = src_ip
                    # ospf_hello_first.neighbors = [neighbor_ip]
                    ospf_packet_hellofull = ospf_hello_full
                    ospf_packet_hello2 = eth / ip_broadcast_hello / ospf_header / ospf_packet_hellofull
                    sendp(ospf_packet_hello2, iface=interface, verbose=0)
                    # print(f"{ospf_packet_hello2.show()}")
                    print(f"Sent OSPF Hello packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
        elif ospfhdr_layer.type == 2:  # DBD packet
            src_ip = packet[IP].src
            ip2 = ipaddress.IPv4Address(src_ip)
            ip1 = tracking_state.get(interface, {}).get("ip_address")
            netmask1 = tracking_state.get(interface, {}).get("netmask")
            network1 = ipaddress.IPv4Network(f"{ip1}/{netmask1}", strict=False)

            # if neighbor_state == "2-Way":
            #     if ip2 in network1 and src_ip not in ips:
            #         print("Received DBD packet")
            #         neighbor_state = "Exstart"
            #         print(f"Received DBD from {src_ip}, moving to Exstart state")
            #         send_ospf_dbd_first(src_ip, seq_random)
            #         print(f"Sent DBD packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
                # neighbor_state = "Exstart"
                # print(f"Received DBD from {src_ip}, moving to Exstart state")
                # send_ospf_dbd_first(src_ip, seq_random)
            if tracking_state.get(interface, {}).get("state") == "2-Way":
                if ip2 in network1 and src_ip not in ips:
                    dbd_layer = packet.getlayer(OSPF_DBDesc)
                    if dbd_layer.dbdescr == 0x00:
                        jumlah_lsa = len(dbd_layer.lsaheaders)
                        # print(f"{dbd_layer.show()}")
                        # print(f"Jumlah LSA: {jumlah_lsa}")
                        router_status = "Master"
                        # print(f"{router_status} DBD")
                        seq_exchange = dbd_layer.ddseq
                        print(f"Received DBD from {src_ip}, moving to Exchange state as Master")
                        tracking_state[interface]["state"] = "Exchange"
                        # send_ospf_dbd_first(src_ip, seq_random)
                        send_ospf_dbd(interface, src_broadcast, source_ip,src_ip)
                        print(f"Sent DBD packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
                        
                        for i in range(jumlah_lsa): #add LSA to list
                            lsa = dbd_layer.lsaheaders[i]
                            lsadb_list.append(lsa)
                    #     print(f"LSA {i+1}: ID: {lsa.id}, Type: {lsa.adrouter}, Sequence Number: {lsa.seq}")
                        print(f"LSA List: {lsadb_list}")
                        send_ospf_lsr(interface, src_broadcast, source_ip,src_ip) #kirim LSR ke neighbor

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
                    
                    
        elif ospfhdr_layer.type == 3:  # LSR packet
            print("Received LSR packet")
            src_ip = packet[IP].src
            ip2 = ipaddress.IPv4Address(src_ip)
            ip1 = tracking_state.get(interface, {}).get("ip_address")
            netmask1 = tracking_state.get(interface, {}).get("netmask")
            network1 = ipaddress.IPv4Network(f"{ip1}/{netmask1}", strict=False)

            if tracking_state.get(interface, {}).get("state") == "Exchange":
                if ip2 in network1 and src_ip not in ips:
                    lsr_layer = packet.getlayer(OSPF_LSReq)
                    jumlah_lsreq = len(lsr_layer.requests)
                    print(f"Received LSR from {src_ip}, ready to Full state")
                    tracking_state[interface]["state"] = "Loading"

                    for i in range(jumlah_lsreq):
                        lsr = lsr_layer.requests[i]
                        lsreqdb_list.append(lsr)
                        # print(f"LSR {i+1}: ID: {lsr.id}, Type: {lsr.adrouter}")

                    send_ospf_lsu(interface, src_broadcast, source_ip,src_ip)
                    print(f"Sent LSU packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")


        elif ospfhdr_layer.type == 4:  # LSU packet
            print("Received LSU packet")
            src_ip = packet[IP].src
            ip2 = ipaddress.IPv4Address(src_ip)
            ip1 = tracking_state.get(interface, {}).get("ip_address")
            netmask1 = tracking_state.get(interface, {}).get("netmask")
            network1 = ipaddress.IPv4Network(f"{ip1}/{netmask1}", strict=False)

            if tracking_state.get(interface, {}).get("state") == "Loading" or "Exchange":
                if  ip2 in network1 and src_ip not in ips:
                    lsu_layer = packet.getlayer(OSPF_LSUpd)
                    ether_layer = packet.getlayer(Ether)
                    jumlah_lsulsa = lsu_layer.lsacount
                    print(f"Received LSU from {src_ip}, moving to Full state")
                    tracking_state[interface]["state"] = "Full"
                    mac_src = ether_layer.src
                    for i in range(jumlah_lsulsa):
                        lsalsu = lsu_layer.lsalist[i]
                        lsackdb_list.append(lsalsu)
                        # print(f"LSU {i+1}: ID: {lsalsu.id}, Type: {lsalsu.adrouter}")
                    # print(f"LSA List: {len(lsackdb_list)}")
                    print(f"LSA List: {lsackdb_list}")
                    ip_lsu2 = IP(src=src_broadcast, dst=broadcast_ip)
    
                    # Header OSPF tipe 4: Link State Update Packet
                    ospf_hdr_lsu2 = OSPF_Hdr(version=2, type=4, src=source_ip, area=area_id)
                    
                    lsalist45= [OSPF_Router_LSA(
                                age = 3300, # Age of the LSA
                                options=0x02, # Options field
                                type=1,  # Router LSA
                                id="192.168.1.2", # LSA ID
                                adrouter="192.168.1.2 ", # Advertising router
                                seq=seq_global,  # Sequence number
                                linkcount=totallink, # Number of links
                                linklist=[
                                    OSPF_Link(id="10.10.1.2", data="10.10.1.2", type=2, metric=1),
                                    OSPF_Link(id="192.168.1.0", data="255.255.255.0", type=3, metric=1)
                                    # OSPF_Link(id="11.11.1.2", data="11.11.1.2", type=2, metric=1)
                                ] # List of links
                            ), OSPF_Network_LSA(
                                age = 3300, # Age of the LSA
                                options=option_default, # Options field
                                type=2,  # Network LSA
                                id="10.10.1.2", # LSA ID
                                adrouter="192.168.1.2", # Advertising router
                                seq=0x80000123,  # Sequence number
                                mask="255.255.255.0", # Subnet mask
                                routerlist=["10.10.1.1", "192.168.1.2"] # List of routers
                            )]

                    lsanew = lsackdb_list
                    # print(f"LSA New List: {lsanew}")
                    lsanew.extend(lsalist45)
                    # print(f"LSA New List: {lsanew}")
                    z = len(lsanew)
                    # lsackdb_list.extend(lsalist2)
                    if penghitung == 0:
                        ospf_lsu_pkt45 = (eth /
                                            ip_lsu2 /
                                            ospf_hdr_lsu2 /
                                            OSPF_LSUpd(
                                                lsacount=z,
                                                lsalist= lsanew
                                            )     
                                        )
                        sendp(ospf_lsu_pkt45, iface=interface, verbose=0)
                        penghitung = penghitung + 1
                    else:
                        return
                    

                    # if penghitung == 0:
                        
                    #     penghitung = penghitung + 1
                    # else:
                    #     return
                    send_ospf_lsaack(interface, src_broadcast, source_ip, broadcast_ip)
                    print(f"Sent LS_ACK packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
            if tracking_state.get(interface, {}).get("state") == "Full":
                if  ip2 in network1 and src_ip not in ips:
                    lsu_layer = packet.getlayer(OSPF_LSUpd)
                    jumlah_lsulsa = lsu_layer.lsacount
                    print(f"Received LSU from {src_ip}, moving to Full state")
                    tracking_state[interface]["state"] = "Full"
                    for i in range(jumlah_lsulsa):
                        lsalsu = lsu_layer.lsalist[i]
                        lsackdb_list.append(lsalsu)
                        print(f"LSU {i+1}: ID: {lsalsu.id}, Type: {lsalsu.type}, Advertising Router: {lsalsu.adrouter}, sequence: {lsalsu.seq}")
                    # print(f"LSA List: {len(lsackdb_list)}")
                    send_ospf_lsaack(interface, src_broadcast, source_ip,broadcast_ip)                    
                    print(f"Sent LS_ACK packet to {src_ip} at {time.strftime('%Y-%m-%d %H:%M:%S')} - State: {neighbor_state}")
        # elif ospfhdr_layer.type == 5:  # LSAck packet
        #     print("Received LSAck packet")
        #     src_ip = packet[IP].src
        #     ip2 = ipaddress.IPv4Address(src_ip)
        #     ip1 = tracking_state.get(interface, {}).get("ip_address")
        #     netmask1 = tracking_state.get(interface, {}).get("netmask")
        #     network1 = ipaddress.IPv4Network(f"{ip1}/{netmask1}", strict=False)
            
        #     if tracking_state.get(interface, {}).get("state") == "Full":
        #         if ip2 in network1 and src_ip not in ips:
        #             # lsack_layer = packet.getlayer(OSPF_LSAck)
        #             # jumlah_lsack = len(lsack_layer.lsaheaders)
        #             print(f"Received LSAck from {src_ip}, moving to Full state")
        #             tracking_state[interface]["state"] = "Full"
        #             send_ospf_lsaack(interface, src_broadcast, source_ip,broadcastip)

def sniff_packets(interface, src_broadcast, source_ip):
   print("Sniffing packets...")
   sniff(iface=interface , filter="ip proto ospf", prn=lambda pkt: handle_incoming_packet(pkt, interface,src_broadcast,source_ip), store=False, timeout=100000000)

if __name__ == "__main__":
    
    threads = []

    interfaces_info = get_interfaces_info_with_interface_name()

    for info in interfaces_info:
        # tracking_state.append(neighbors_state)
        iplist = ipaddress.IPv4Address(info['ip_address'])

        if target_ip < iplist:
            target_ip = iplist
            source_ip = str(target_ip)
        elif target_ip == iplist:
            # print(f"Interface: {info['interface']}")
            continue
        elif target_ip > iplist:
            source_ip = str(target_ip)


        if info['interface'] != 'ens4':

            tracking_state[info['interface']] = {
                "state": "Down",
                "ip_address": info['ip_address'],
                "netmask": info['netmask'],
                }
            
            hello_thread = threading.Thread(target=lambda : send_hello_periodically(10, info['interface'], info['ip_address'], source_ip))
            hello_thread.daemon=True
            hello_thread.start()
            threads.append(hello_thread)
    
            recv_thread = threading.Thread(target=lambda : sniff_packets(info['interface'], info['ip_address'], source_ip))
            recv_thread.daemon=True
            recv_thread.start()
            threads.append(recv_thread)
        else:
            continue

    ospf_header = OSPF_Hdr(version=2, type=1, src=source_ip, area=area_id)
    print(f"thread: {threads}")
    print(f"neighbors_state: {tracking_state}")

    try:
        while True:
            time.sleep(1)
          
    except KeyboardInterrupt:
        print("Program terminated by user.")