#!/usr/bin/env python3
"""
OSPF Router Implementation using Scapy
Implements full OSPF neighbor adjacency process
"""

import socket
import struct
import time
import threading
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
import hashlib
import random

# OSPF Constants
OSPF_VERSION = 2
OSPF_HELLO = 1
OSPF_DB_DESC = 2
OSPF_LSR = 3
OSPF_LSU = 4
OSPF_LSA_ACK = 5

# OSPF States
STATE_DOWN = 0
STATE_INIT = 1
STATE_2WAY = 2
STATE_EXSTART = 3
STATE_EXCHANGE = 4
STATE_LOADING = 5
STATE_FULL = 6

# LSA Types
LSA_ROUTER = 1
LSA_NETWORK = 2
LSA_SUMMARY = 3
LSA_ASBR_SUMMARY = 4
LSA_EXTERNAL = 5

class OSPFHeader:
    def __init__(self, msg_type, router_id, area_id=0):
        self.version = OSPF_VERSION
        self.type = msg_type
        self.length = 24  # Base OSPF header length
        self.router_id = router_id
        self.area_id = area_id
        self.checksum = 0
        self.auth_type = 0
        self.auth_data = b'\x00' * 8

    def pack(self):
        return struct.pack('!BBHHIIHH8s',
                          self.version, self.type, self.length,
                          self.checksum, self.router_id, self.area_id,
                          self.auth_type, 0, self.auth_data)

class OSPFHello:
    def __init__(self, router_id, network_mask, hello_interval=10, dead_interval=40):
        self.network_mask = network_mask
        self.hello_interval = hello_interval
        self.options = 0x02  # E-bit set
        self.priority = 1
        self.dead_interval = dead_interval
        self.designated_router = 0
        self.backup_designated_router = 0
        self.neighbors = []

    def pack(self):
        data = struct.pack('!IHBBI',
                          self.interface_mtu, self.hello_interval,
                          self.options, self.priority,
                          self.dead_interval)
        data += struct.pack('!II', self.designated_router, self.backup_designated_router)
        for neighbor in self.neighbors:
            data += struct.pack('!I', neighbor)
        return data

class OSPFDatabaseDescription:
    def __init__(self, interface_mtu=1500, options=0x02, flags=0x07, dd_sequence=0):
        self.interface_mtu = interface_mtu
        self.options = options
        self.flags = flags  # I-bit, M-bit, MS-bit
        self.dd_sequence = dd_sequence
        self.lsa_headers = []

    def pack(self):
        data = struct.pack('!HBBI',
                          self.interface_mtu, self.options,
                          self.flags, self.dd_sequence)
        for lsa_header in self.lsa_headers:
            data += lsa_header.pack()
        return data

class LSAHeader:
    def __init__(self, lsa_type, link_state_id, advertising_router, sequence=0x80000001):
        self.age = 0
        self.options = 0x02
        self.type = lsa_type
        self.link_state_id = link_state_id
        self.advertising_router = advertising_router
        self.sequence = sequence
        self.checksum = 0
        self.length = 20

    def pack(self):
        return struct.pack('!HBBIIIHH',
                          self.age, self.options, self.type,
                          self.link_state_id, self.advertising_router,
                          self.sequence, self.checksum, self.length)

class OSPFNeighbor:
    def __init__(self, router_id, ip_address):
        self.router_id = router_id
        self.ip_address = ip_address
        self.state = STATE_DOWN
        self.priority = 1
        self.designated_router = 0
        self.backup_designated_router = 0
        self.last_hello = time.time()
        self.dd_sequence = random.randint(1, 0xFFFFFFFF)
        self.master = False
        self.lsa_list = {}
        self.lsr_list = []

    def is_alive(self, dead_interval=40):
        return (time.time() - self.last_hello) < dead_interval

class OSPFRouter:
    def __init__(self, router_id, interface_name, interface_ip, network_mask, area_id=0):
        self.router_id = self._ip_to_int(router_id)
        self.interface_name = interface_name
        self.interface_ip = interface_ip
        self.interface_ip_int = self._ip_to_int(interface_ip)
        self.network_mask = self._ip_to_int(network_mask)
        self.area_id = area_id
        
        self.neighbors = {}
        self.lsdb = {}  # Link State Database
        self.hello_interval = 10
        self.dead_interval = 40
        
        self.socket = None
        self.running = False
        
        # Sequence numbers
        self.dd_sequence = random.randint(1, 0xFFFFFFFF)
        
        print(f"OSPF Router initialized:")
        print(f"  Router ID: {router_id} ({self.router_id})")
        print(f"  Interface: {interface_name} ({interface_ip})")
        print(f"  Network: {interface_ip}/{self._int_to_ip(network_mask)}")

    def _ip_to_int(self, ip_str):
        """Convert IP string to integer"""
        return struct.unpack('!I', socket.inet_aton(ip_str))[0]

    def _int_to_ip(self, ip_int):
        """Convert integer to IP string"""
        return socket.inet_ntoa(struct.pack('!I', ip_int))

    def _calculate_checksum(self, data):
        """Calculate OSPF checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i + 1]
        
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        return (~checksum) & 0xFFFF

    def start(self):
        """Start OSPF router"""
        self.running = True
        
        # Create raw socket for OSPF (protocol 89)
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.interface_ip, 0))
        except PermissionError:
            print("Error: Root privileges required for raw socket")
            return
        except Exception as e:
            print(f"Error creating socket: {e}")
            return

        print("OSPF Router started")
        
        # Start threads
        threading.Thread(target=self._hello_sender, daemon=True).start()
        threading.Thread(target=self._packet_receiver, daemon=True).start()
        threading.Thread(target=self._neighbor_monitor, daemon=True).start()

    def stop(self):
        """Stop OSPF router"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("OSPF Router stopped")

    def _hello_sender(self):
        """Send Hello packets periodically"""
        while self.running:
            try:
                self._send_hello()
                time.sleep(self.hello_interval)
            except Exception as e:
                print(f"Error sending hello: {e}")

    def _send_hello(self):
        """Send OSPF Hello packet"""
        # Create OSPF header
        header = OSPFHeader(OSPF_HELLO, self.router_id, self.area_id)
        
        # Create Hello packet
        hello = OSPFHello(self.router_id, self.network_mask,
                         self.hello_interval, self.dead_interval)
        
        # Add known neighbors
        hello.neighbors = list(self.neighbors.keys())
        
        # Pack data - fix Hello format
        hello_data = struct.pack('!I', self.network_mask)  # Network mask first
        hello_data += struct.pack('!HBBI', self.hello_interval, 0x02, 1, self.dead_interval)  # Hello interval, options, priority, dead interval
        hello_data += struct.pack('!II', 0, 0)  # DR and BDR (0 for now)
        
        # Add neighbors
        for neighbor_id in hello.neighbors:
            hello_data += struct.pack('!I', neighbor_id)
        
        header.length = 24 + len(hello_data)
        header_data = header.pack()
        
        # Calculate checksum
        packet_data = header_data + hello_data
        checksum_data = packet_data[:12] + b'\x00\x00' + packet_data[14:]
        checksum = self._calculate_checksum(checksum_data)
        
        # Update checksum in packet
        packet_data = packet_data[:12] + struct.pack('!H', checksum) + packet_data[14:]
        
        # Send to multicast address
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.sendto(packet_data, ('224.0.0.5', 0))
            sock.close()
            print(f"Hello sent to 224.0.0.5 (neighbors: {len(hello.neighbors)})")
        except Exception as e:
            print(f"Error sending hello packet: {e}")

    def _packet_receiver(self):
        """Receive and process OSPF packets"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(65535)
                if addr[0] != self.interface_ip:  # Don't process our own packets
                    self._process_packet(data, addr[0])
            except Exception as e:
                if self.running:
                    print(f"Error receiving packet: {e}")

    def _process_packet(self, data, src_ip):
        """Process received OSPF packet"""
        if len(data) < 24:
            return

        # Parse OSPF header
        version, msg_type, length, checksum, router_id, area_id, auth_type, auth_reserved = struct.unpack('!BBHHIIHH', data[:20])
        auth_data = data[20:24]
        
        if version != OSPF_VERSION or area_id != self.area_id:
            return

        print(f"Received OSPF packet type {msg_type} from {self._int_to_ip(router_id)} ({src_ip})")

        if msg_type == OSPF_HELLO:
            self._process_hello(data[24:], router_id, src_ip)
        elif msg_type == OSPF_DB_DESC:
            self._process_db_desc(data[24:], router_id, src_ip)
        elif msg_type == OSPF_LSR:
            self._process_lsr(data[24:], router_id, src_ip)
        elif msg_type == OSPF_LSU:
            self._process_lsu(data[24:], router_id, src_ip)
        elif msg_type == OSPF_LSA_ACK:
            self._process_lsa_ack(data[24:], router_id, src_ip)

    def _process_hello(self, data, router_id, src_ip):
        """Process Hello packet"""
        if len(data) < 24:
            return

        # First 4 bytes is network mask, then hello interval
        network_mask, hello_interval, options, priority = struct.unpack('!IHBB', data[:8])
        dead_interval, dr, bdr = struct.unpack('!III', data[8:20])
        
        # Parse neighbors
        neighbors = []
        offset = 20
        while offset + 4 <= len(data):
            neighbor_id = struct.unpack('!I', data[offset:offset+4])[0]
            neighbors.append(neighbor_id)
            offset += 4

        # Check if we're in the neighbor list (2-way communication)
        bidirectional = self.router_id in neighbors

        # Update or create neighbor
        if router_id not in self.neighbors:
            self.neighbors[router_id] = OSPFNeighbor(router_id, src_ip)
            print(f"New neighbor discovered: {self._int_to_ip(router_id)} ({src_ip})")

        neighbor = self.neighbors[router_id]
        neighbor.last_hello = time.time()
        neighbor.priority = priority
        neighbor.designated_router = dr
        neighbor.backup_designated_router = bdr

        # State machine
        old_state = neighbor.state
        
        if neighbor.state == STATE_DOWN:
            neighbor.state = STATE_INIT
        
        if neighbor.state == STATE_INIT and bidirectional:
            neighbor.state = STATE_2WAY
            print(f"Neighbor {self._int_to_ip(router_id)} reached 2-Way state")
            
            # Start database exchange
            self._start_database_exchange(neighbor)

        if old_state != neighbor.state:
            print(f"Neighbor {self._int_to_ip(router_id)} state: {old_state} -> {neighbor.state}")

    def _start_database_exchange(self, neighbor):
        """Start database description exchange"""
        neighbor.state = STATE_EXSTART
        neighbor.master = neighbor.router_id > self.router_id
        
        if neighbor.master:
            print(f"We are SLAVE to {self._int_to_ip(neighbor.router_id)}")
        else:
            print(f"We are MASTER to {self._int_to_ip(neighbor.router_id)}")
            # Send initial DD packet
            self._send_db_desc(neighbor, initial=True)

    def _send_db_desc(self, neighbor, initial=False):
        """Send Database Description packet"""
        header = OSPFHeader(OSPF_DB_DESC, self.router_id, self.area_id)
        
        flags = 0
        if initial:
            flags |= 0x04  # I-bit (Initial)
        if not neighbor.master:
            flags |= 0x01  # MS-bit (Master)
        if len(self.lsdb) > 0:
            flags |= 0x02  # M-bit (More)

        dd = OSPFDatabaseDescription(flags=flags, dd_sequence=self.dd_sequence)
        
        # Add LSA headers from our database
        for lsa_key, lsa_data in list(self.lsdb.items())[:5]:  # Limit for demo
            lsa_header = LSAHeader(LSA_ROUTER, lsa_key, self.router_id)
            dd.lsa_headers.append(lsa_header)

        dd_data = dd.pack()
        header.length = 24 + len(dd_data)
        header_data = header.pack()
        
        packet_data = header_data + dd_data
        checksum_data = packet_data[:12] + b'\x00\x00' + packet_data[14:]
        checksum = self._calculate_checksum(checksum_data)
        packet_data = packet_data[:12] + struct.pack('!H', checksum) + packet_data[14:]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)
            sock.sendto(packet_data, (neighbor.ip_address, 0))
            sock.close()
            print(f"Database Description sent to {neighbor.ip_address}")
        except Exception as e:
            print(f"Error sending DD packet: {e}")

    def _process_db_desc(self, data, router_id, src_ip):
        """Process Database Description packet"""
        if router_id not in self.neighbors:
            return

        neighbor = self.neighbors[router_id]
        
        if len(data) < 8:
            return

        interface_mtu, options, flags, dd_sequence = struct.unpack('!HBBI', data[:8])
        
        print(f"DB Desc from {self._int_to_ip(router_id)}: flags={flags:02x}, seq={dd_sequence}")

        # Parse LSA headers
        offset = 8
        lsa_headers = []
        while offset + 20 <= len(data):
            lsa_data = data[offset:offset+20]
            lsa_headers.append(lsa_data)
            offset += 20

        # State machine processing
        if neighbor.state == STATE_EXSTART:
            if flags & 0x04:  # I-bit set
                neighbor.state = STATE_EXCHANGE
                if neighbor.master:
                    neighbor.dd_sequence = dd_sequence
                    self._send_db_desc(neighbor)
                print(f"Neighbor {self._int_to_ip(router_id)} entered Exchange state")

        elif neighbor.state == STATE_EXCHANGE:
            # Process LSA headers and build LSR list
            for lsa_header in lsa_headers:
                # Check if we need this LSA
                neighbor.lsr_list.append(lsa_header)
            
            if not (flags & 0x02):  # M-bit not set - no more DD packets
                if neighbor.lsr_list:
                    neighbor.state = STATE_LOADING
                    self._send_lsr(neighbor)
                    print(f"Neighbor {self._int_to_ip(router_id)} entered Loading state")
                else:
                    neighbor.state = STATE_FULL
                    print(f"Neighbor {self._int_to_ip(router_id)} reached FULL adjacency!")

    def _send_lsr(self, neighbor):
        """Send Link State Request"""
        if not neighbor.lsr_list:
            return

        header = OSPFHeader(OSPF_LSR, self.router_id, self.area_id)
        
        # Take first few LSAs to request
        lsr_data = b''
        for lsa_header in neighbor.lsr_list[:5]:  # Limit requests
            lsr_data += lsa_header[:12]  # First 12 bytes identify the LSA

        header.length = 24 + len(lsr_data)
        header_data = header.pack()
        
        packet_data = header_data + lsr_data
        checksum_data = packet_data[:12] + b'\x00\x00' + packet_data[14:]
        checksum = self._calculate_checksum(checksum_data)
        packet_data = packet_data[:12] + struct.pack('!H', checksum) + packet_data[14:]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)
            sock.sendto(packet_data, (neighbor.ip_address, 0))
            sock.close()
            print(f"Link State Request sent to {neighbor.ip_address}")
        except Exception as e:
            print(f"Error sending LSR: {e}")

    def _process_lsr(self, data, router_id, src_ip):
        """Process Link State Request"""
        print(f"Link State Request received from {self._int_to_ip(router_id)}")
        
        # Send LSU with requested LSAs (simplified)
        if router_id in self.neighbors:
            self._send_lsu(self.neighbors[router_id])

    def _send_lsu(self, neighbor):
        """Send Link State Update"""
        header = OSPFHeader(OSPF_LSU, self.router_id, self.area_id)
        
        # Create a simple router LSA
        num_lsas = 1
        lsu_data = struct.pack('!I', num_lsas)
        
        # Router LSA
        router_lsa = self._create_router_lsa()
        lsu_data += router_lsa

        header.length = 24 + len(lsu_data)
        header_data = header.pack()
        
        packet_data = header_data + lsu_data
        checksum_data = packet_data[:12] + b'\x00\x00' + packet_data[14:]
        checksum = self._calculate_checksum(checksum_data)
        packet_data = packet_data[:12] + struct.pack('!H', checksum) + packet_data[14:]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)
            sock.sendto(packet_data, (neighbor.ip_address, 0))
            sock.close()
            print(f"Link State Update sent to {neighbor.ip_address}")
        except Exception as e:
            print(f"Error sending LSU: {e}")

    def _create_router_lsa(self):
        """Create Router LSA"""
        lsa_header = LSAHeader(LSA_ROUTER, self.router_id, self.router_id)
        
        # Router LSA body
        flags = 0x00  # Not ASBR, not ABR
        num_links = 1
        
        # Link to our network
        link_id = self.interface_ip_int & self.network_mask
        link_data = self.interface_ip_int
        link_type = 3  # Stub network
        num_tos = 0
        metric = 1

        lsa_body = struct.pack('!BBHIIBBHI',
                              flags, 0, num_links,
                              link_id, link_data,
                              link_type, num_tos, metric)

        lsa_header.length = 20 + len(lsa_body)
        
        return lsa_header.pack() + lsa_body

    def _process_lsu(self, data, router_id, src_ip):
        """Process Link State Update"""
        if len(data) < 4:
            return

        num_lsas = struct.unpack('!I', data[:4])[0]
        print(f"Link State Update from {self._int_to_ip(router_id)}: {num_lsas} LSAs")
        
        # Send LSA ACK
        if router_id in self.neighbors:
            self._send_lsa_ack(self.neighbors[router_id], data[4:])
            
            # Update neighbor state to FULL if in LOADING
            neighbor = self.neighbors[router_id]
            if neighbor.state == STATE_LOADING:
                neighbor.state = STATE_FULL
                print(f"Neighbor {self._int_to_ip(router_id)} reached FULL adjacency!")

    def _send_lsa_ack(self, neighbor, lsa_data):
        """Send LSA Acknowledgment"""
        header = OSPFHeader(OSPF_LSA_ACK, self.router_id, self.area_id)
        
        # Extract LSA headers for acknowledgment
        ack_data = b''
        offset = 0
        while offset + 20 <= len(lsa_data):
            ack_data += lsa_data[offset:offset+20]  # LSA header only
            # Skip to next LSA
            lsa_length = struct.unpack('!H', lsa_data[offset+18:offset+20])[0]
            offset += lsa_length

        header.length = 24 + len(ack_data)
        header_data = header.pack()
        
        packet_data = header_data + ack_data
        checksum_data = packet_data[:12] + b'\x00\x00' + packet_data[14:]
        checksum = self._calculate_checksum(checksum_data)
        packet_data = packet_data[:12] + struct.pack('!H', checksum) + packet_data[14:]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)
            sock.sendto(packet_data, (neighbor.ip_address, 0))
            sock.close()
            print(f"LSA Acknowledgment sent to {neighbor.ip_address}")
        except Exception as e:
            print(f"Error sending LSA ACK: {e}")

    def _process_lsa_ack(self, data, router_id, src_ip):
        """Process LSA Acknowledgment"""
        print(f"LSA Acknowledgment received from {self._int_to_ip(router_id)}")

    def _neighbor_monitor(self):
        """Monitor neighbor states and handle dead neighbors"""
        while self.running:
            current_time = time.time()
            dead_neighbors = []
            
            for router_id, neighbor in self.neighbors.items():
                if not neighbor.is_alive(self.dead_interval):
                    dead_neighbors.append(router_id)
                    print(f"Neighbor {self._int_to_ip(router_id)} declared dead")

            for dead_id in dead_neighbors:
                del self.neighbors[dead_id]

            time.sleep(5)

    def show_neighbors(self):
        """Display current neighbors"""
        print("\nOSPF Neighbors:")
        print("-" * 80)
        print(f"{'Router ID':<15} {'IP Address':<15} {'State':<10} {'Priority':<8} {'Dead Time':<10}")
        print("-" * 80)
        
        current_time = time.time()
        for router_id, neighbor in self.neighbors.items():
            state_names = ["Down", "Init", "2-Way", "ExStart", "Exchange", "Loading", "Full"]
            state_name = state_names[neighbor.state] if neighbor.state < len(state_names) else "Unknown"
            dead_time = int(self.dead_interval - (current_time - neighbor.last_hello))
            
            print(f"{self._int_to_ip(router_id):<15} {neighbor.ip_address:<15} {state_name:<10} {neighbor.priority:<8} {dead_time:<10}")

def main():
    """Main function to run OSPF router"""
    print("OSPF Router Implementation")
    print("=" * 50)
    
    # Configuration for your setup
    router_id = "10.10.1.2"  # Same as interface IP
    interface_name = "ens4"
    interface_ip = "10.10.1.2"
    network_mask = "255.255.255.0"
    area_id = 0
    
    # Create and start OSPF router
    ospf_router = OSPFRouter(router_id, interface_name, interface_ip, network_mask, area_id)
    
    try:
        ospf_router.start()
        
        print("\nOSPF Router is running...")
        print("Commands:")
        print("  'neighbors' - Show neighbor table")
        print("  'quit' - Stop router")
        
        while True:
            try:
                cmd = input("\nOSPF> ").strip().lower()
                
                if cmd == 'quit':
                    break
                elif cmd == 'neighbors':
                    ospf_router.show_neighbors()
                elif cmd == '':
                    continue
                else:
                    print("Unknown command")
                    
            except KeyboardInterrupt:
                break
                
    except Exception as e:
        print(f"Error: {e}")
    finally:
        ospf_router.stop()

if __name__ == "__main__":
    main()