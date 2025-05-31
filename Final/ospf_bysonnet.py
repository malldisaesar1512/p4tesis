#!/usr/bin/env python3
"""
OSPF Implementation untuk Ubuntu
Menangani seluruh proses OSPF dari Hello packet hingga Full state
"""

import socket
import struct
import time
import threading
import hashlib
import ipaddress
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import json

# OSPF Constants
OSPF_VERSION = 2
OSPF_HELLO = 1
OSPF_DB_DESC = 2
OSPF_LSR = 3
OSPF_LSU = 4
OSPF_LSA_ACK = 5

# LSA Types
LSA_ROUTER = 1
LSA_NETWORK = 2
LSA_SUMMARY = 3
LSA_ASBR_SUMMARY = 4
LSA_EXTERNAL = 5

# OSPF States
class OSPFState(Enum):
    DOWN = 0
    INIT = 1
    TWO_WAY = 2
    EXSTART = 3
    EXCHANGE = 4
    LOADING = 5
    FULL = 6

@dataclass
class OSPFNeighbor:
    router_id: str
    ip_address: str
    state: OSPFState
    priority: int
    designated_router: str
    backup_designated_router: str
    last_hello: float
    dd_sequence: int
    master: bool
    more_bit: bool
    init_bit: bool
    lsa_list: List = None
    
    def __post_init__(self):
        if self.lsa_list is None:
            self.lsa_list = []

@dataclass
class LSAHeader:
    age: int
    options: int
    type: int
    link_state_id: str
    advertising_router: str
    sequence: int
    checksum: int
    length: int

@dataclass
class LSA:
    header: LSAHeader
    data: bytes

class OSPFRouter:
    def __init__(self, router_id: str, area_id: str = "0.0.0.0"):
        self.router_id = router_id
        self.area_id = area_id
        self.interfaces = {}
        self.neighbors = {}
        self.lsdb = {}  # Link State Database
        self.sequence_number = 0x80000001
        self.socket = None
        self.running = False
        
        # Interface configurations
        self.interface_configs = {
            'ens3': {
                'ip': '192.168.1.2',
                'mask': '255.255.255.0',
                'hello_interval': 10,
                'dead_interval': 40,
                'priority': 1
            },
            'ens4': {
                'ip': '10.10.1.2', 
                'mask': '255.255.255.0',
                'hello_interval': 10,
                'dead_interval': 40,
                'priority': 1
            }
        }
        
    def start(self):
        """Start OSPF process"""
        self.running = True
        self.setup_socket()
        
        # Generate our own Router LSA
        self.generate_router_lsa()
        
        # Start threads
        threading.Thread(target=self.listen_packets, daemon=True).start()
        threading.Thread(target=self.send_hello_packets, daemon=True).start()
        threading.Thread(target=self.neighbor_timeout_check, daemon=True).start()
        
        print(f"OSPF Router {self.router_id} started")
        
    def setup_socket(self):
        """Setup raw socket untuk OSPF"""
        try:
            # Create raw socket for OSPF protocol (89)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Enable IP header inclusion
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Join multicast group for OSPF
            mreq = struct.pack('4s4s', socket.inet_aton('224.0.0.5'), socket.inet_aton('0.0.0.0'))
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            # Set multicast TTL
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            
            print("Raw socket setup completed")
            
        except PermissionError:
            print("Error: Butuh sudo privileges untuk raw socket")
            exit(1)
        except Exception as e:
            print(f"Socket setup error: {e}")
            exit(1)
            
    def create_ip_header(self, source_ip: str, dest_ip: str, ospf_length: int) -> bytes:
        """Create IP header for OSPF packet"""
        ip_ihl = 5  # Internet Header Length
        ip_ver = 4  # IP Version
        ip_tos = 0xc0  # Type of Service (DSCP for routing protocols)
        ip_tot_len = 20 + ospf_length  # IP header + OSPF packet
        ip_id = 54321  # Identification
        ip_frag_off = 0  # Fragment offset
        ip_ttl = 1  # TTL for multicast
        ip_proto = 89  # OSPF protocol
        ip_check = 0  # Checksum (will be calculated by kernel)
        ip_saddr = struct.unpack('!I', socket.inet_aton(source_ip))[0]
        ip_daddr = struct.unpack('!I', socket.inet_aton(dest_ip))[0]
        
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        # Pack IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               ip_ihl_ver,    # Version and IHL
                               ip_tos,        # Type of Service
                               ip_tot_len,    # Total Length
                               ip_id,         # Identification
                               ip_frag_off,   # Flags and Fragment Offset
                               ip_ttl,        # TTL
                               ip_proto,      # Protocol
                               ip_check,      # Header Checksum
                               struct.pack('!I', ip_saddr),  # Source Address
                               struct.pack('!I', ip_daddr)   # Destination Address
                               )
        return ip_header
        
    def create_ospf_header(self, packet_type: int, length: int, source_ip: str) -> bytes:
        """Create OSPF header"""
        header = struct.pack('!BBHIHHI',
            OSPF_VERSION,           # Version
            packet_type,            # Type
            length,                 # Length
            struct.unpack('!I', socket.inet_aton(self.router_id))[0],  # Router ID
            struct.unpack('!I', socket.inet_aton(self.area_id))[0],    # Area ID
            0,                      # Checksum (will be calculated)
            0                       # Authentication Type
        )
        
        # Authentication Data (8 bytes of zeros for no auth)
        auth_data = b'\x00' * 8
        
        return header + auth_data
        
    def calculate_checksum(self, data: bytes) -> int:
        """Calculate OSPF checksum"""
        if len(data) % 2:
            data += b'\x00'
            
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += struct.unpack('!H', data[i:i+2])[0]
            
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16
        
        return ~checksum & 0xFFFF
        
    def create_hello_packet(self, interface: str) -> bytes:
        """Create OSPF Hello packet"""
        config = self.interface_configs[interface]
        
        # Hello packet data
        hello_data = struct.pack('!IBBBBI',
            struct.unpack('!I', socket.inet_aton(config['mask']))[0],  # Network Mask
            config['hello_interval'],                                   # Hello Interval
            0,                                                         # Options
            config['priority'],                                        # Router Priority
            config['dead_interval'],                                   # Router Dead Interval
            0                                                          # Designated Router
        )
        
        # Backup Designated Router
        hello_data += struct.pack('!I', 0)
        
        # Add neighbors
        for neighbor_id in self.neighbors:
            hello_data += struct.pack('!I', struct.unpack('!I', socket.inet_aton(neighbor_id))[0])
            
        packet_length = 24 + len(hello_data)  # OSPF header + Hello data
        header = self.create_ospf_header(OSPF_HELLO, packet_length, config['ip'])
        
        packet = header + hello_data
        
        # Calculate and insert checksum
        checksum = self.calculate_checksum(packet)
        packet = packet[:12] + struct.pack('!H', checksum) + packet[14:]
        
        return packet
        
    def send_hello_packets(self):
        """Periodically send Hello packets"""
        while self.running:
            for interface, config in self.interface_configs.items():
                try:
                    hello_packet = self.create_hello_packet(interface)
                    
                    # Create complete packet with IP header
                    ip_header = self.create_ip_header(config['ip'], '224.0.0.5', len(hello_packet))
                    complete_packet = ip_header + hello_packet
                    
                    # Send to multicast address 224.0.0.5
                    dest_addr = ('224.0.0.5', 0)
                    bytes_sent = self.socket.sendto(complete_packet, dest_addr)
                    
                    print(f"Sent Hello packet on {interface} ({config['ip']}) - {bytes_sent} bytes")
                    
                except Exception as e:
                    print(f"Error sending Hello on {interface}: {e}")
                    import traceback
                    traceback.print_exc()
                    
            time.sleep(10)  # Send every 10 seconds
            
    def listen_packets(self):
        """Listen for incoming OSPF packets"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(65535)
                
                # Skip IP header (first 20 bytes) to get OSPF packet
                if len(data) > 20:
                    ospf_data = data[20:]
                    self.process_packet(ospf_data, addr[0])
                    
            except Exception as e:
                print(f"Error receiving packet: {e}")
                import traceback
                traceback.print_exc()
                
    def process_packet(self, data: bytes, source_ip: str):
        """Process incoming OSPF packet"""
        if len(data) < 24:  # Minimum OSPF header size
            return
            
        # Parse OSPF header
        header = struct.unpack('!BBHIHHI', data[:16])
        version = header[0]
        packet_type = header[1] 
        length = header[2]
        router_id = socket.inet_ntoa(struct.pack('!I', header[3]))
        area_id = socket.inet_ntoa(struct.pack('!I', header[4]))
        
        if version != OSPF_VERSION or area_id != self.area_id:
            return
            
        print(f"Received OSPF packet type {packet_type} from {router_id} ({source_ip})")
        
        if packet_type == OSPF_HELLO:
            self.process_hello_packet(data[24:], router_id, source_ip)
        elif packet_type == OSPF_DB_DESC:
            self.process_dd_packet(data[24:], router_id, source_ip)
        elif packet_type == OSPF_LSR:
            self.process_lsr_packet(data[24:], router_id, source_ip)
        elif packet_type == OSPF_LSU:
            self.process_lsu_packet(data[24:], router_id, source_ip)
        elif packet_type == OSPF_LSA_ACK:
            self.process_lsa_ack_packet(data[24:], router_id, source_ip)
            
    def process_hello_packet(self, data: bytes, router_id: str, source_ip: str):
        """Process Hello packet"""
        if len(data) < 20:
            return
            
        # Parse Hello packet
        hello_info = struct.unpack('!IBBBBI', data[:16])
        network_mask = socket.inet_ntoa(struct.pack('!I', hello_info[0]))
        hello_interval = hello_info[1]
        priority = hello_info[3]
        dead_interval = hello_info[4]
        designated_router = socket.inet_ntoa(struct.pack('!I', hello_info[5]))
        
        backup_dr = socket.inet_ntoa(struct.pack('!I', struct.unpack('!I', data[16:20])[0]))
        
        # Parse neighbor list
        neighbors_data = data[20:]
        neighbors = []
        for i in range(0, len(neighbors_data), 4):
            if i + 4 <= len(neighbors_data):
                neighbor_id = socket.inet_ntoa(struct.pack('!I', struct.unpack('!I', neighbors_data[i:i+4])[0]))
                neighbors.append(neighbor_id)
        
        print(f"Hello from {router_id}: DR={designated_router}, BDR={backup_dr}, Neighbors={neighbors}")
        
        # Update or create neighbor
        if router_id not in self.neighbors:
            self.neighbors[router_id] = OSPFNeighbor(
                router_id=router_id,
                ip_address=source_ip,
                state=OSPFState.INIT,
                priority=priority,
                designated_router=designated_router,
                backup_designated_router=backup_dr,
                last_hello=time.time(),
                dd_sequence=0,
                master=False,
                more_bit=False,
                init_bit=False
            )
            print(f"New neighbor {router_id} in INIT state")
        else:
            neighbor = self.neighbors[router_id]
            neighbor.last_hello = time.time()
            neighbor.designated_router = designated_router
            neighbor.backup_designated_router = backup_dr
            
        # Check if we are in neighbor's neighbor list
        if self.router_id in neighbors:
            neighbor = self.neighbors[router_id]
            if neighbor.state == OSPFState.INIT:
                neighbor.state = OSPFState.TWO_WAY
                print(f"Neighbor {router_id} moved to TWO-WAY state")
                
                # Start Database Description exchange
                self.start_dd_exchange(router_id)
                
    def start_dd_exchange(self, neighbor_id: str):
        """Start Database Description exchange"""
        neighbor = self.neighbors[neighbor_id]
        
        # Determine master/slave relationship
        if self.router_id > neighbor_id:
            neighbor.master = False
            neighbor.dd_sequence = int(time.time()) & 0xFFFF
            neighbor.state = OSPFState.EXSTART
            print(f"Starting DD exchange with {neighbor_id} as MASTER")
            self.send_dd_packet(neighbor_id, initial=True)
        else:
            neighbor.master = True
            neighbor.state = OSPFState.EXSTART
            print(f"Starting DD exchange with {neighbor_id} as SLAVE")
            
    def send_dd_packet(self, neighbor_id: str, initial: bool = False):
        """Send Database Description packet"""
        neighbor = self.neighbors[neighbor_id]
        
        # DD packet flags
        flags = 0
        if not neighbor.master:  # We are master
            flags |= 0x01  # Master bit
        if initial or len(self.lsdb) > 0:
            flags |= 0x02  # More bit
        if initial:
            flags |= 0x04  # Init bit
            
        # Create DD packet
        dd_data = struct.pack('!HBxI',
            1500,                    # Interface MTU
            flags,                   # Options and flags
            neighbor.dd_sequence     # DD sequence number
        )
        
        # Add LSA headers from our database
        for lsa_key, lsa in self.lsdb.items():
            lsa_header = struct.pack('!HBBIIIH',
                lsa.header.age,
                lsa.header.options,
                lsa.header.type,
                struct.unpack('!I', socket.inet_aton(lsa.header.link_state_id))[0],
                struct.unpack('!I', socket.inet_aton(lsa.header.advertising_router))[0],
                lsa.header.sequence,
                lsa.header.length
            )
            dd_data += lsa_header
            
        packet_length = 24 + len(dd_data)
        header = self.create_ospf_header(OSPF_DB_DESC, packet_length, neighbor.ip_address)
    def send_packet_to_neighbor(self, packet_data: bytes, neighbor_id: str, packet_type: str):
        """Send packet to specific neighbor"""
        if neighbor_id not in self.neighbors:
            return
            
        neighbor = self.neighbors[neighbor_id]
        
        try:
            # Determine source IP based on neighbor's network
            source_ip = None
            if neighbor.ip_address.startswith('192.168.1.'):
                source_ip = self.interface_configs['ens3']['ip']
            elif neighbor.ip_address.startswith('10.10.1.'):
                source_ip = self.interface_configs['ens4']['ip']
            else:
                source_ip = self.interface_configs['ens4']['ip']  # Default
                
            # Create complete packet with IP header
            ip_header = self.create_ip_header(source_ip, neighbor.ip_address, len(packet_data))
            complete_packet = ip_header + packet_data
            
            bytes_sent = self.socket.sendto(complete_packet, (neighbor.ip_address, 0))
            print(f"Sent {packet_type} to {neighbor_id} ({neighbor.ip_address}) - {bytes_sent} bytes")
            
        except Exception as e:
            print(f"Error sending {packet_type} to {neighbor_id}: {e}")
            import traceback
            traceback.print_exc()
            
    def process_dd_packet(self, data: bytes, router_id: str, source_ip: str):
        """Process Database Description packet"""
        if router_id not in self.neighbors or len(data) < 8:
            return
            
        neighbor = self.neighbors[router_id]
        
        # Parse DD packet
        dd_info = struct.unpack('!HBxI', data[:8])
        interface_mtu = dd_info[0]
        flags = dd_info[1]
        dd_sequence = dd_info[2]
        
        master_bit = flags & 0x01
        more_bit = flags & 0x02
        init_bit = flags & 0x04
        
        print(f"Received DD from {router_id}: seq={dd_sequence}, M={more_bit}, I={init_bit}, MS={master_bit}")
        
        if neighbor.state == OSPFState.EXSTART:
            if init_bit and master_bit and not neighbor.master:
                # Neighbor claims to be master
                neighbor.dd_sequence = dd_sequence
                neighbor.state = OSPFState.EXCHANGE
                print(f"Neighbor {router_id} is master, moving to EXCHANGE")
                
                # Send DD response
                self.send_dd_packet(router_id)
                
        elif neighbor.state == OSPFState.EXCHANGE:
            # Process LSA headers
            lsa_headers_data = data[8:]
            self.process_lsa_headers(lsa_headers_data, router_id)
            
            if not more_bit:
                neighbor.state = OSPFState.LOADING
                print(f"DD exchange complete with {router_id}, moving to LOADING")
                
                # Request missing LSAs
                self.send_lsr_packet(router_id)
                
    def process_lsa_headers(self, data: bytes, neighbor_id: str):
        """Process LSA headers from DD packet"""
        offset = 0
        while offset + 20 <= len(data):
            header_data = data[offset:offset + 20]
            lsa_header = struct.unpack('!HBBIIIH', header_data)
            
            age = lsa_header[0]
            options = lsa_header[1] 
            lsa_type = lsa_header[2]
            link_state_id = socket.inet_ntoa(struct.pack('!I', lsa_header[3]))
            advertising_router = socket.inet_ntoa(struct.pack('!I', lsa_header[4]))
            sequence = lsa_header[5]
            length = lsa_header[6]
            
            lsa_key = f"{lsa_type}:{link_state_id}:{advertising_router}"
            
            # Check if we need this LSA
            if lsa_key not in self.lsdb:
                print(f"Need LSA: {lsa_key}")
                # Add to request list for this neighbor
                neighbor = self.neighbors[neighbor_id]
                if not hasattr(neighbor, 'lsa_requests'):
                    neighbor.lsa_requests = []
                neighbor.lsa_requests.append((lsa_type, link_state_id, advertising_router))
                
            offset += 20
            
    def send_lsr_packet(self, neighbor_id: str):
        """Send Link State Request packet"""
        neighbor = self.neighbors[neighbor_id]
        
        if not hasattr(neighbor, 'lsa_requests') or not neighbor.lsa_requests:
            # No LSAs to request, move to FULL
            neighbor.state = OSPFState.FULL
            print(f"No LSAs to request from {neighbor_id}, moving to FULL state")
            return
            
        # Create LSR packet
        lsr_data = b''
        for lsa_type, link_state_id, advertising_router in neighbor.lsa_requests:
            lsr_entry = struct.pack('!III',
                lsa_type,
                struct.unpack('!I', socket.inet_aton(link_state_id))[0],
                struct.unpack('!I', socket.inet_aton(advertising_router))[0]
            )
            lsr_data += lsr_entry
            
        packet_length = 24 + len(lsr_data)
        header = self.create_ospf_header(OSPF_LSR, packet_length, neighbor.ip_address)
        packet = header + lsr_data
        
        # Calculate checksum
        checksum = self.calculate_checksum(packet)
        packet = packet[:12] + struct.pack('!H', checksum) + packet[14:]
        
        # Send using helper method
        self.send_packet_to_neighbor(packet, neighbor_id, "DD packet")
        
        try:
            self.socket.sendto(packet, (neighbor.ip_address, 0))
            print(f"Sent LSR packet to {neighbor_id} requesting {len(neighbor.lsa_requests)} LSAs")
        except Exception as e:
            print(f"Error sending LSR packet: {e}")
            
    def process_lsr_packet(self, data: bytes, router_id: str, source_ip: str):
        """Process Link State Request packet"""
        print(f"Received LSR from {router_id}")
        
        # Parse LSR entries
        requested_lsas = []
        offset = 0
        while offset + 12 <= len(data):
            lsr_entry = struct.unpack('!III', data[offset:offset + 12])
            lsa_type = lsr_entry[0]
            link_state_id = socket.inet_ntoa(struct.pack('!I', lsr_entry[1]))
            advertising_router = socket.inet_ntoa(struct.pack('!I', lsr_entry[2]))
            
            lsa_key = f"{lsa_type}:{link_state_id}:{advertising_router}"
            if lsa_key in self.lsdb:
                requested_lsas.append(self.lsdb[lsa_key])
                
            offset += 12
            
        # Send LSU with requested LSAs
        if requested_lsas:
            self.send_lsu_packet(router_id, requested_lsas)
            
    def send_lsu_packet(self, neighbor_id: str, lsas: List[LSA]):
        """Send Link State Update packet"""
        neighbor = self.neighbors[neighbor_id]
        
        # Create LSU packet
        lsu_data = struct.pack('!I', len(lsas))  # Number of LSAs
        
        for lsa in lsas:
            # Add complete LSA
            lsa_header = struct.pack('!HBBIIIH',
                lsa.header.age,
                lsa.header.options,
                lsa.header.type,
                struct.unpack('!I', socket.inet_aton(lsa.header.link_state_id))[0],
                struct.unpack('!I', socket.inet_aton(lsa.header.advertising_router))[0],
                lsa.header.sequence,
                lsa.header.length
            )
            lsu_data += lsa_header + lsa.data
            
        packet_length = 24 + len(lsu_data)
        header = self.create_ospf_header(OSPF_LSU, packet_length, neighbor.ip_address)
        packet = header + lsu_data
        
        # Calculate checksum
        checksum = self.calculate_checksum(packet)
        packet = packet[:12] + struct.pack('!H', checksum) + packet[14:]
        
        # Send using helper method
        self.send_packet_to_neighbor(packet, neighbor_id, f"LSU packet ({len(lsas)} LSAs)")
            
    def process_lsu_packet(self, data: bytes, router_id: str, source_ip: str):
        """Process Link State Update packet"""
        if len(data) < 4:
            return
            
        num_lsas = struct.unpack('!I', data[:4])[0]
        print(f"Received LSU from {router_id} with {num_lsas} LSAs")
        
        # Parse LSAs
        offset = 4
        lsa_headers_for_ack = []
        
        for i in range(num_lsas):
            if offset + 20 > len(data):
                break
                
            # Parse LSA header
            header_data = data[offset:offset + 20]
            lsa_header_raw = struct.unpack('!HBBIIIH', header_data)
            
            age = lsa_header_raw[0]
            options = lsa_header_raw[1]
            lsa_type = lsa_header_raw[2] 
            link_state_id = socket.inet_ntoa(struct.pack('!I', lsa_header_raw[3]))
            advertising_router = socket.inet_ntoa(struct.pack('!I', lsa_header_raw[4]))
            sequence = lsa_header_raw[5]
            length = lsa_header_raw[6]
            
            # Extract LSA data
            lsa_data = data[offset + 20:offset + length]
            
            # Create LSA object
            lsa_header = LSAHeader(age, options, lsa_type, link_state_id, 
                                 advertising_router, sequence, 0, length)
            lsa = LSA(lsa_header, lsa_data)
            
            # Store in LSDB
            lsa_key = f"{lsa_type}:{link_state_id}:{advertising_router}"
            self.lsdb[lsa_key] = lsa
            lsa_headers_for_ack.append(lsa_header)
            
            print(f"Installed LSA: {lsa_key}")
            offset += length
            
        # Send LSA ACK
        self.send_lsa_ack_packet(router_id, lsa_headers_for_ack)
        
        # Check if neighbor can move to FULL state
        if router_id in self.neighbors:
            neighbor = self.neighbors[router_id]
            if neighbor.state == OSPFState.LOADING:
                neighbor.state = OSPFState.FULL
                print(f"Neighbor {router_id} moved to FULL state")
                
    def send_lsa_ack_packet(self, neighbor_id: str, lsa_headers: List[LSAHeader]):
        """Send LSA Acknowledgment packet"""
        neighbor = self.neighbors[neighbor_id]
        
        # Create LSA ACK packet
        ack_data = b''
        for header in lsa_headers:
            lsa_header_data = struct.pack('!HBBIIIH',
                header.age,
                header.options,
                header.type,
                struct.unpack('!I', socket.inet_aton(header.link_state_id))[0],
                struct.unpack('!I', socket.inet_aton(header.advertising_router))[0],
                header.sequence,
                header.length
            )
            ack_data += lsa_header_data
            
        packet_length = 24 + len(ack_data)
        header = self.create_ospf_header(OSPF_LSA_ACK, packet_length, neighbor.ip_address)
        packet = header + ack_data
        
        # Calculate checksum
        checksum = self.calculate_checksum(packet)
        packet = packet[:12] + struct.pack('!H', checksum) + packet[14:]
        
        # Send using helper method
        self.send_packet_to_neighbor(packet, neighbor_id, f"LSA ACK ({len(lsa_headers)} LSAs)")
            
    def process_lsa_ack_packet(self, data: bytes, router_id: str, source_ip: str):
        """Process LSA Acknowledgment packet"""
        num_headers = len(data) // 20
        print(f"Received LSA ACK from {router_id} for {num_headers} LSAs")
        
        # Process each acknowledged LSA header
        for i in range(num_headers):
            offset = i * 20
            if offset + 20 <= len(data):
                header_data = data[offset:offset + 20]
                # Process acknowledgment (remove from retransmission list, etc.)
                
    def neighbor_timeout_check(self):
        """Check for neighbor timeouts"""
        while self.running:
            current_time = time.time()
            dead_neighbors = []
            
            for neighbor_id, neighbor in self.neighbors.items():
                if current_time - neighbor.last_hello > 40:  # Dead interval
                    print(f"Neighbor {neighbor_id} timed out")
                    dead_neighbors.append(neighbor_id)
                    
            for neighbor_id in dead_neighbors:
                del self.neighbors[neighbor_id]
                
            time.sleep(5)  # Check every 5 seconds
            
    def print_status(self):
        """Print current OSPF status"""
        print(f"\n=== OSPF Router {self.router_id} Status ===")
        print(f"Area: {self.area_id}")
        print(f"Neighbors: {len(self.neighbors)}")
        
        for neighbor_id, neighbor in self.neighbors.items():
            print(f"  {neighbor_id} ({neighbor.ip_address}) - State: {neighbor.state.name}")
            
        print(f"LSDB Entries: {len(self.lsdb)}")
        for lsa_key in self.lsdb:
            print(f"  {lsa_key}")
        print()
        
    def generate_router_lsa(self):
        """Generate Router LSA for this router"""
        # Router LSA Type 1
        lsa_data = struct.pack('!BBH',
            0,  # Flags
            0,  # Reserved
            2   # Number of links (ens3 and ens4)
        )
        
        # Link 1: ens3 interface
        link1_data = struct.pack('!IIBBB',
            struct.unpack('!I', socket.inet_aton('192.168.1.0'))[0],  # Link ID
            struct.unpack('!I', socket.inet_aton('255.255.255.0'))[0], # Link Data
            1,  # Type (stub network)
            0,  # Number of TOS
            10  # Metric
        )
        
        # Link 2: ens4 interface  
        link2_data = struct.pack('!IIBBB',
            struct.unpack('!I', socket.inet_aton('10.10.1.0'))[0],   # Link ID
            struct.unpack('!I', socket.inet_aton('255.255.255.0'))[0], # Link Data
            1,  # Type (stub network)
            0,  # Number of TOS
            10  # Metric
        )
        
        lsa_data += link1_data + link2_data
        
        # Create LSA header
        header = LSAHeader(
            age=0,
            options=0,
            type=LSA_ROUTER,
            link_state_id=self.router_id,
            advertising_router=self.router_id,
            sequence=self.sequence_number,
            checksum=0,
            length=20 + len(lsa_data)
        )
        
        lsa = LSA(header, lsa_data)
        lsa_key = f"{LSA_ROUTER}:{self.router_id}:{self.router_id}"
        self.lsdb[lsa_key] = lsa
        self.sequence_number += 1
        
        print(f"Generated Router LSA: {lsa_key}")
        return lsa
        
    def calculate_routes(self):
        """Simple SPF calculation from LSDB"""
        print("\n=== Route Calculation ===")
        
        # Simple route extraction from Router LSAs
        routes = {}
        
        for lsa_key, lsa in self.lsdb.items():
            if lsa.header.type == LSA_ROUTER:
                advertising_router = lsa.header.advertising_router
                print(f"Processing Router LSA from {advertising_router}")
                
                # Parse router LSA data
                if len(lsa.data) >= 4:
                    num_links = struct.unpack('!H', lsa.data[2:4])[0]
                    print(f"  Router has {num_links} links")
                    
                    offset = 4
                    for i in range(num_links):
                        if offset + 12 <= len(lsa.data):
                            link_info = struct.unpack('!IIBBB', lsa.data[offset:offset+12])
                            link_id = socket.inet_ntoa(struct.pack('!I', link_info[0]))
                            link_data = socket.inet_ntoa(struct.pack('!I', link_info[1]))
                            link_type = link_info[2]
                            metric = link_info[4]
                            
                            if link_type == 1:  # Stub network
                                print(f"    Stub network: {link_id} via {advertising_router}, metric {metric}")
                                routes[link_id] = {
                                    'via': advertising_router,
                                    'metric': metric,
                                    'type': 'stub'
                                }
                            
                            offset += 12
        
        print(f"\nTotal routes discovered: {len(routes)}")
        for network, route_info in routes.items():
            print(f"  {network} via {route_info['via']} (metric {route_info['metric']})")
        
        return routes

def main():
    """Main function"""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: sudo python3 ospf_router.py <router_id>")
        print("Example: sudo python3 ospf_router.py 1.1.1.1")
        sys.exit(1)
        
    router_id = sys.argv[1]
    
    # Create and start OSPF router
    ospf_router = OSPFRouter(router_id)
    ospf_router.start()
    
    print("OSPF Router started. Press Ctrl+C to stop.")
    print("Use 'status' command to check neighbor states.")
    
    try:
        while True:
            cmd = input("> ").strip().lower()
            if cmd == 'status':
                ospf_router.print_status()
            elif cmd == 'quit' or cmd == 'exit':
                break
            elif cmd == 'neighbors':
                print("Current neighbors:")
                for nid, neighbor in ospf_router.neighbors.items():
                    print(f"  {nid}: {neighbor.state.name}")
            elif cmd == 'lsdb':
                print("Link State Database:")
                for lsa_key in ospf_router.lsdb:
                    print(f"  {lsa_key}")
            elif cmd == 'routes':
                print("Calculating routes from LSDB...")
                ospf_router.calculate_routes()
            elif cmd == 'generate':
                print("Regenerating Router LSA...")
                ospf_router.generate_router_lsa()
            elif cmd == 'debug':
                print("Debug information:")
                print(f"  Socket: {ospf_router.socket}")
                print(f"  Running: {ospf_router.running}")
                print(f"  Interfaces: {list(ospf_router.interface_configs.keys())}")
                for iface, config in ospf_router.interface_configs.items():
                    print(f"    {iface}: {config['ip']}")
            elif cmd == 'test':
                print("Sending test Hello packet...")
                try:
                    hello_packet = ospf_router.create_hello_packet('ens4')
                    ip_header = ospf_router.create_ip_header('10.10.1.2', '224.0.0.5', len(hello_packet))
                    complete_packet = ip_header + hello_packet
                    bytes_sent = ospf_router.socket.sendto(complete_packet, ('224.0.0.5', 0))
                    print(f"Test packet sent: {bytes_sent} bytes")
                except Exception as e:
                    print(f"Test failed: {e}")
                    import traceback
                    traceback.print_exc()
                    
    except KeyboardInterrupt:
        pass
    finally:
        ospf_router.running = False
        print("\nOSPF Router stopped.")

if __name__ == "__main__":
    main()