#!/usr/bin/env python3

import os
import sys
import time
import socket
import random
import struct
import threading
import subprocess
import ipaddress
from datetime import datetime
import psutil

# OSPF Constants
OSPF_VERSION = 2
OSPF_TYPE_HELLO = 1
OSPF_TYPE_DBD = 2
OSPF_TYPE_LSR = 3
OSPF_TYPE_LSU = 4
OSPF_TYPE_LSACK = 5

# OSPF Options (Mikrotik compatible)
OSPF_OPTIONS_E = 0x02  # External Routing
OSPF_OPTIONS_DC = 0x04  # Demand Circuits
OSPF_OPTIONS_O = 0x10  # Opaque LSA
OSPF_OPTIONS_DN = 0x20  # DN bit
OSPF_OPTIONS_ALL = OSPF_OPTIONS_E | OSPF_OPTIONS_DC  # Default options

# OSPF States
OSPF_STATE_DOWN = 0
OSPF_STATE_INIT = 1
OSPF_STATE_2WAY = 2
OSPF_STATE_EXSTART = 3
OSPF_STATE_EXCHANGE = 4
OSPF_STATE_LOADING = 5
OSPF_STATE_FULL = 6

# Mikrotik-optimized defaults
hello_interval = 10
dead_interval = 40
priority_default = 1
backup_default = "0.0.0.0"
broadcast_ip = "224.0.0.5"
area_id = "0.0.0.0"
router_id = "10.10.1.2"
initial_sequence_number = 0x80000001

# State tracking
tracking_state = {}
lsadb = {}
neighbors = {}
retransmit_queue = {}

def fletcher_checksum(data):
    """Calculate Fletcher checksum for OSPF"""
    c0 = c1 = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            w = (data[i] << 8) + data[i + 1]
        else:
            w = (data[i] << 8)
        c0 = (c0 + w) % 255
        c1 = (c1 + c0) % 255
    return (c1 << 8) | c0

# Fletcher-16 checksum for OSPF
def checksum(data):
    """Calculate the checksum for the given data using Fletcher-16 algorithm."""
    if len(data) % 2 == 1:
        data += b'\x00'  # Pad with zero byte if length is odd

    sum1 = 255
    sum2 = 255

    for i in range(0, len(data), 2):
        sum1 = (sum1 + data[i]) % 255
        sum2 = (sum2 + sum1) % 255
        if i + 1 < len(data):
            sum1 = (sum1 + data[i + 1]) % 255
            sum2 = (sum2 + sum1) % 255

    return (sum2 << 8) | sum1

# OSPF Packet class
class OSPFPacket:
    """Base class for OSPF packet creation"""
    def __init__(self):
        self.version = OSPF_VERSION
        self.packet_type = 0
        self.packet_length = 0
        self.router_id = router_id
        self.area_id = area_id
        self.checksum = 0
        self.auth_type = 0
        self.auth_data = 0
        self.sequence_number = initial_sequence_number

    def calculate_checksum(self, data):
        """Calculate OSPF checksum over packet data"""
        # Zero out checksum field for calculation
        data = data[:12] + b'\x00\x00' + data[14:]
        return fletcher_checksum(data)

    def build_header(self):
        """Build OSPF header with proper checksum"""
        header = struct.pack("!BBHLLHQ",
            self.version,
            self.packet_type,
            self.packet_length,
            int(ipaddress.IPv4Address(self.router_id)),
            int(ipaddress.IPv4Address(self.area_id)),
            0,  # Checksum will be calculated later
            self.auth_data
        )
        return header

# OSPF Hello packet class
class OSPFHello(OSPFPacket):
    """OSPF Hello packet builder with Mikrotik compatibility"""
    def __init__(self, src_ip=None):
        super().__init__()
        self.packet_type = OSPF_TYPE_HELLO
        self.network_mask = "255.255.255.0"
        self.hello_interval = hello_interval
        self.options = OSPF_OPTIONS_ALL
        self.priority = priority_default
        self.dead_interval = dead_interval
        self.designated_router = backup_default
        self.backup_router = backup_default
        self.neighbors = []
        self.src_ip = src_ip

    def build(self):
        """Build complete Hello packet with proper checksum"""
        # Build Hello specific fields
        hello_data = struct.pack("!LHBBLL",
            int(ipaddress.IPv4Address(self.network_mask)),
            self.hello_interval,
            self.options,
            self.priority,
            self.dead_interval,
            int(ipaddress.IPv4Address(self.designated_router))
        )
        
        # Add backup router
        hello_data += struct.pack("!L",
            int(ipaddress.IPv4Address(self.backup_router))
        )
        
        # Add neighbors
        for neighbor in self.neighbors:
            hello_data += struct.pack("!L",
                int(ipaddress.IPv4Address(neighbor))
            )
            
        # Calculate total length and update header
        self.packet_length = 44 + len(self.neighbors) * 4
        
        # Build complete packet
        header = self.build_header()
        packet = header + hello_data
        
        # Calculate and set checksum
        self.checksum = self.calculate_checksum(packet)
        
        # Rebuild with correct checksum
        header = struct.pack("!BBHLLHQ",
            self.version,
            self.packet_type,
            self.packet_length,
            int(ipaddress.IPv4Address(self.router_id)),
            int(ipaddress.IPv4Address(self.area_id)),
            self.checksum,
            self.auth_data
        )
        
        return header + hello_data

def create_ospf_socket(interface):
    """Create raw socket for OSPF communication with multicast support"""
    try:
        # Create raw socket for OSPF
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_OSPF)
        
        # Enable IP header inclusion
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # Enable broadcast and add to multicast group
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Join OSPF multicast group
        mreq = struct.pack("4s4s", 
            socket.inet_aton(broadcast_ip),
            socket.inet_aton("0.0.0.0"))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        
        return sock
    except PermissionError:
        print("Error: Root privileges required to create raw socket")
        sys.exit(1)
    except Exception as e:
        print(f"Error creating socket: {e}")
        sys.exit(1)

def send_hello_packet(interface, src_ip, neighbors=None):
    """Send OSPF Hello packet with proper neighbor list"""
    if neighbors is None:
        neighbors = []
        
    try:
        # Create Hello packet with source IP
        hello = OSPFHello(src_ip)
        hello.neighbors = neighbors
        
        # Get interface state
        state = tracking_state[interface]
        
        # Set DR/BDR if known
        if state["dr"]:
            hello.designated_router = state["dr"]
        if state["bdr"]:
            hello.backup_router = state["bdr"]
        
        packet_data = hello.build()
        
        # Create and configure socket
        sock = create_ospf_socket(interface)
        
        # Send packet
        sock.sendto(packet_data, (broadcast_ip, 0))
        sock.close()
        
        # Update last hello sent time
        state["last_hello"] = time.time()
        return True
        
    except Exception as e:
        print(f"Error sending Hello packet: {e}")
        return False

def start_ospf_process(interface, src_ip):
    """Start OSPF process with full state machine"""
    # Initialize interface state
    tracking_state[interface] = {
        "state": OSPF_STATE_DOWN,
        "neighbors": set(),
        "dr": None,
        "bdr": None,
        "last_hello": 0,
        "sequence_number": initial_sequence_number,
        "retransmit_queue": []
    }
    
    def check_dead_neighbors():
        """Check for dead neighbors"""
        while True:
            current_time = time.time()
            state = tracking_state[interface]
            dead_neighbors = set()
            
            for neighbor in state["neighbors"]:
                if neighbor not in neighbors:
                    neighbors[neighbor] = {"last_hello": 0}
                    
                if current_time - neighbors[neighbor]["last_hello"] > dead_interval:
                    dead_neighbors.add(neighbor)
            
            # Remove dead neighbors
            for neighbor in dead_neighbors:
                state["neighbors"].remove(neighbor)
                del neighbors[neighbor]
                
                # Trigger DR election if needed
                if neighbor == state["dr"] or neighbor == state["bdr"]:
                    elect_dr(interface)
            
            time.sleep(dead_interval / 4)
    
    def elect_dr(interface):
        """Elect Designated Router and Backup Designated Router"""
        state = tracking_state[interface]
        candidates = list(state["neighbors"]) + [router_id]
        
        if not candidates:
            state["dr"] = None
            state["bdr"] = None
            return
            
        # Sort by router ID (highest wins in Mikrotik)
        candidates.sort(reverse=True)
        
        if len(candidates) >= 1:
            state["dr"] = candidates[0]
        if len(candidates) >= 2:
            state["bdr"] = candidates[1]

def process_ospf_packet(data, interface, src_ip):
    """Process received OSPF packet with full state machine"""
    try:
        # Parse OSPF header (first 24 bytes)
        version, packet_type, length, rid, aid, checksum, auth = struct.unpack("!BBHLLHQ", data[:24])
        
        if version != OSPF_VERSION:
            return
            
        # Convert router ID to string
        src_router = socket.inet_ntoa(struct.pack("!L", rid))
        
        # Verify checksum
        expected_checksum = fletcher_checksum(data[:12] + b'\x00\x00' + data[14:])
        if checksum != expected_checksum:
            print(f"Invalid checksum from {src_router}")
            return
            
        # Process based on packet type
        if packet_type == OSPF_TYPE_HELLO:
            process_hello_packet(data[24:], interface, src_ip, src_router)
        elif packet_type == OSPF_TYPE_DBD:
            process_database_description(data[24:], interface, src_ip, src_router)
        elif packet_type == OSPF_TYPE_LSR:
            process_link_state_request(data[24:], interface, src_ip, src_router)
        elif packet_type == OSPF_TYPE_LSU:
            process_link_state_update(data[24:], interface, src_ip, src_router)
        elif packet_type == OSPF_TYPE_LSACK:
            process_link_state_ack(data[24:], interface, src_ip, src_router)
            
    except Exception as e:
        print(f"Error processing packet: {e}")

def process_hello_packet(data, interface, src_ip, src_router):
    """Process OSPF Hello packet with state transitions"""
    try:
        # Parse Hello packet fields
        mask, hello_int, options, priority, dead_int, dr, bdr = struct.unpack("!LHBBLL", data[:20])
        
        # Get neighbor list from remaining data
        neighbor_count = (len(data) - 20) // 4
        neighbors = []
        for i in range(neighbor_count):
            n = struct.unpack("!L", data[20+i*4:24+i*4])[0]
            neighbors.append(socket.inet_ntoa(struct.pack("!L", n)))
            
        # Update neighbor state
        state = tracking_state[interface]
        
        # Create/update neighbor entry
        if src_router not in neighbors:
            neighbors[src_router] = {
                "state": OSPF_STATE_DOWN,
                "last_hello": time.time(),
                "dr_priority": priority,
                "options": options
            }
            
        neighbor = neighbors[src_router]
        neighbor["last_hello"] = time.time()
        
        # State machine transitions
        if neighbor["state"] == OSPF_STATE_DOWN:
            if router_id in neighbors:
                # Two-way communication established
                neighbor["state"] = OSPF_STATE_2WAY
                state["neighbors"].add(src_router)
                elect_dr(interface)
        elif neighbor["state"] == OSPF_STATE_INIT:
            if router_id in neighbors:
                neighbor["state"] = OSPF_STATE_2WAY
                
        # Update DR/BDR information
        if dr != 0:
            dr_ip = socket.inet_ntoa(struct.pack("!L", dr))
            state["dr"] = dr_ip
        if bdr != 0:
            bdr_ip = socket.inet_ntoa(struct.pack("!L", bdr))
            state["bdr"] = bdr_ip
            
    except Exception as e:
        print(f"Error processing Hello packet: {e}")

def process_database_description(data, interface, src_ip, src_router):
    """Process Database Description packets"""
    try:
        # Parse DBD header (8 bytes)
        mtu, options, flags, seq = struct.unpack("!HBBL", data[:8])
        
        # Extract LSA headers
        lsa_count = (len(data) - 8) // 20
        lsa_headers = []
        
        for i in range(lsa_count):
            offset = 8 + i * 20
            age, opts, type_, id_, adv, seq, csum, length = struct.unpack("!HBBLLHH", data[offset:offset+20])
            lsa_headers.append({
                "age": age,
                "type": type_,
                "id": socket.inet_ntoa(struct.pack("!L", id_)),
                "adv_router": socket.inet_ntoa(struct.pack("!L", adv)),
                "seq": seq
            })
            
        # Update neighbor state
        state = tracking_state[interface]
        if src_router in neighbors:
            neighbor = neighbors[src_router]
            
            if neighbor["state"] == OSPF_STATE_2WAY:
                neighbor["state"] = OSPF_STATE_EXSTART
                
            elif neighbor["state"] == OSPF_STATE_EXSTART:
                if flags & 0x07:  # Init, More, Master bits
                    neighbor["state"] = OSPF_STATE_EXCHANGE
                    
            elif neighbor["state"] == OSPF_STATE_EXCHANGE:
                # Process LSA headers and request missing LSAs
                request_list = []
                for lsa in lsa_headers:
                    if needs_update(lsa):
                        request_list.append(lsa)
                        
                if request_list:
                    send_link_state_request(interface, src_ip, src_router, request_list)
                    
    except Exception as e:
        print(f"Error processing DBD packet: {e}")

def process_link_state_request(data, interface, src_ip, src_router):
    """Process Link State Request packets"""
    try:
        # Parse LSR entries (12 bytes each)
        request_count = len(data) // 12
        requests = []
        
        for i in range(request_count):
            offset = i * 12
            type_, _, id_, adv = struct.unpack("!LLL", data[offset:offset+12])
            requests.append({
                "type": type_,
                "id": socket.inet_ntoa(struct.pack("!L", id_)),
                "adv_router": socket.inet_ntoa(struct.pack("!L", adv))
            })
            
        # Send requested LSAs
        if requests:
            lsas = []
            for req in requests:
                lsa = find_lsa(req["type"], req["id"], req["adv_router"])
                if lsa:
                    lsas.append(lsa)
                    
            if lsas:
                send_link_state_update(interface, src_ip, src_router, lsas)
                
    except Exception as e:
        print(f"Error processing LSR packet: {e}")

def process_link_state_update(data, interface, src_ip, src_router):
    """Process Link State Update packets"""
    try:
        # Parse LSU header (4 bytes)
        lsa_count, = struct.unpack("!L", data[:4])
        offset = 4
        
        acks = []  # LSAs to acknowledge
        
        # Process each LSA
        for _ in range(lsa_count):
            # Parse LSA header (20 bytes)
            age, opts, type_, id_, adv, seq, csum, length = struct.unpack("!HBBLLHH", data[offset:offset+20])
            
            # Convert IDs to string format
            lsa_id = socket.inet_ntoa(struct.pack("!L", id_))
            adv_router = socket.inet_ntoa(struct.pack("!L", adv))
            
            # Create LSA entry
            lsa = {
                "age": age,
                "type": type_,
                "id": lsa_id,
                "adv_router": adv_router,
                "seq": seq,
                "checksum": csum,
                "length": length,
                "data": data[offset:offset+length]
            }
            
            # Update LSA database if newer
            if update_lsa(lsa):
                acks.append(lsa)
                
            offset += length
            
        # Send acknowledgment if needed
        if acks:
            send_link_state_ack(interface, src_ip, src_router, acks)
            
    except Exception as e:
        print(f"Error processing LSU packet: {e}")

def process_link_state_ack(data, interface, src_ip, src_router):
    """Process Link State Acknowledgment packets"""
    try:
        # Process LSA headers (20 bytes each)
        ack_count = len(data) // 20
        
        for i in range(ack_count):
            offset = i * 20
            age, opts, type_, id_, adv, seq, csum, length = struct.unpack("!HBBLLHH", data[offset:offset+20])
            
            # Convert IDs to string format
            lsa_id = socket.inet_ntoa(struct.pack("!L", id_))
            adv_router = socket.inet_ntoa(struct.pack("!L", adv))
            
            # Remove from retransmission queue if acknowledged
            remove_from_retransmit_queue(interface, type_, lsa_id, adv_router, seq)
            
    except Exception as e:
        print(f"Error processing LSAck packet: {e}")

def needs_update(lsa):
    """Check if LSA needs to be updated"""
    key = (lsa["type"], lsa["id"], lsa["adv_router"])
    if key in lsadb:
        current = lsadb[key]
        return lsa["seq"] > current["seq"]
    return True

def update_lsa(lsa):
    """Update LSA database if newer"""
    key = (lsa["type"], lsa["id"], lsa["adv_router"])
    if key not in lsadb or lsa["seq"] > lsadb[key]["seq"]:
        lsadb[key] = lsa
        return True
    return False

def remove_from_retransmit_queue(interface, type_, id_, adv_router, seq):
    """Remove acknowledged LSA from retransmission queue"""
    key = (type_, id_, adv_router)
    if interface in retransmit_queue:
        retransmit_queue[interface] = [x for x in retransmit_queue[interface] 
                                     if (x["type"], x["id"], x["adv_router"]) != key or x["seq"] != seq]

def find_lsa(type_, id_, adv_router):
    """Find LSA in database"""
    key = (type_, id_, adv_router)
    return lsadb.get(key)

def send_link_state_request(interface, src_ip, dst_router, requests):
    """Send Link State Request packet"""
    try:
        # Build LSR packet
        packet_data = b""
        for req in requests:
            packet_data += struct.pack("!LLL",
                req["type"],
                int(ipaddress.IPv4Address(req["id"])),
                int(ipaddress.IPv4Address(req["adv_router"]))
            )
            
        # Create OSPF header
        header = OSPFPacket()
        header.packet_type = OSPF_TYPE_LSR
        header.packet_length = 24 + len(packet_data)  # Header + LSR data
        
        # Build complete packet
        packet = header.build_header() + packet_data
        
        # Calculate and set checksum
        checksum = header.calculate_checksum(packet)
        packet = packet[:12] + struct.pack("!H", checksum) + packet[14:]
        
        # Send packet
        sock = create_ospf_socket(interface)
        sock.sendto(packet, (dst_router, 0))
        sock.close()
        
    except Exception as e:
        print(f"Error sending LSR packet: {e}")

def send_link_state_update(interface, src_ip, dst_router, lsas):
    """Send Link State Update packet"""
    try:
        # Build LSU packet
        packet_data = struct.pack("!L", len(lsas))  # Number of LSAs
        
        # Add each LSA
        for lsa in lsas:
            packet_data += lsa["data"]
            
        # Create OSPF header
        header = OSPFPacket()
        header.packet_type = OSPF_TYPE_LSU
        header.packet_length = 24 + len(packet_data)  # Header + LSU data
        
        # Build complete packet
        packet = header.build_header() + packet_data
        
        # Calculate and set checksum
        checksum = header.calculate_checksum(packet)
        packet = packet[:12] + struct.pack("!H", checksum) + packet[14:]
        
        # Send packet
        sock = create_ospf_socket(interface)
        sock.sendto(packet, (dst_router, 0))
        sock.close()
        
        # Add to retransmission queue
        if interface not in retransmit_queue:
            retransmit_queue[interface] = []
        for lsa in lsas:
            retransmit_queue[interface].append(lsa)
            
    except Exception as e:
        print(f"Error sending LSU packet: {e}")

def send_link_state_ack(interface, src_ip, dst_router, lsas):
    """Send Link State Acknowledgment packet"""
    try:
        # Build LSAck packet
        packet_data = b""
        for lsa in lsas:
            # Add LSA header
            packet_data += struct.pack("!HBBLLHH",
                lsa["age"],
                lsa.get("options", 0),
                lsa["type"],
                int(ipaddress.IPv4Address(lsa["id"])),
                int(ipaddress.IPv4Address(lsa["adv_router"])),
                lsa["seq"],
                lsa["checksum"]
            )
            
        # Create OSPF header
        header = OSPFPacket()
        header.packet_type = OSPF_TYPE_LSACK
        header.packet_length = 24 + len(packet_data)  # Header + LSAck data
        
        # Build complete packet
        packet = header.build_header() + packet_data
        
        # Calculate and set checksum
        checksum = header.calculate_checksum(packet)
        packet = packet[:12] + struct.pack("!H", checksum) + packet[14:]
        
        # Send packet
        sock = create_ospf_socket(interface)
        sock.sendto(packet, (dst_router, 0))
        sock.close()
        
    except Exception as e:
        print(f"Error sending LSAck packet: {e}")

def main():
    """Main function with improved interface handling"""
    interfaces_info = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    
    print("OSPF Router Starting...")
    print(f"Router ID: {router_id}")
    print(f"Area ID: {area_id}")
    
    # Find eligible interfaces
    for iface, addr_list in addrs.items():
        is_up = stats[iface].isup if iface in stats else False
        if not is_up:
            continue
            
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ip = addr.address
                netmask = addr.netmask
                if ip and netmask and ip not in ["127.0.0.1"]:
                    interfaces_info.append({
                        "interface": iface,
                        "ip": ip,
                        "netmask": netmask
                    })
                    print(f"Found interface {iface} with IP {ip}")
    
    if not interfaces_info:
        print("No eligible interfaces found")
        sys.exit(1)
    
    print("\nStarting OSPF on interfaces...")
    
    # Start OSPF on each interface
    for info in interfaces_info:
        print(f"Initializing OSPF on {info['interface']} ({info['ip']})")
        start_ospf_process(info["interface"], info["ip"])
    
    print("\nOSPF router running. Press Ctrl+C to exit.")
    
    try:
        while True:
            time.sleep(1)
            
            # Print neighbor summary periodically
            if time.time() % 30 == 0:
                print("\nNeighbor Summary:")
                for iface in tracking_state:
                    state = tracking_state[iface]
                    print(f"\nInterface: {iface}")
                    print(f"State: {state['state']}")
                    print(f"DR: {state['dr'] or 'None'}")
                    print(f"BDR: {state['bdr'] or 'None'}")
                    print(f"Neighbors: {len(state['neighbors'])}")
                    for n in state['neighbors']:
                        print(f"  - {n}")
                print("")
                
    except KeyboardInterrupt:
        print("\nShutting down OSPF router...")
        sys.exit(0)

if __name__ == "__main__":
    main()
