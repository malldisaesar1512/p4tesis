import socket
import struct
from scapy.all import *
from scapy.contrib.ospf import *

# Konfigurasi dasar OSPF
ROUTER_ID = "11.11.1.2"  # ID router untuk node ini
AREA_ID = "0.0.0.0"          # Area OSPF (biasanya backbone area)
HELLO_INTERVAL = 10          # Interval hello packet dalam detik

def create_ospf_hello_packet(dst_ip):
    """Membuat OSPF Hello packet"""
    return IP(dst=dst_ip)/OSPF_Hdr(
        src=ROUTER_ID,
        area=AREA_ID,
        type=1,  # Hello packet
    )/OSPF_Hello(
        mask="255.255.255.0",
        hellointerval=HELLO_INTERVAL,
        options=[],  # Tambahkan opsi jika diperlukan
    )

def process_ospf_packet(packet):
    """Memproses paket OSPF yang masuk"""
    if OSPF_Hdr in packet:
        ospf_header = packet[OSPF_Hdr]
        
        print(f"\n[+] Menerima paket OSPD dari {packet[IP].src}")
        
        if ospf_header.type == 1:  # Hello Packet
            print("   - Jenis: Hello Packet")
            print(f"   - Router ID Pengirim: {ospf_header.src}")
            
            # Membalas dengan Hello Packet ke pengirim asli
            reply_pkt = create_ospf_hello_packet(packet[IP].src)
            send(reply_pkt)
            print(f"[+] Mengirim balasan Hello ke {packet[IP].src}")
            
            return True
        
        elif ospf_header.type == 2:  # Database Description (DBD)
            print("   - Jenis: Database Description")
            
            # Proses DBD dan kirim LSR/LSU jika diperlukan
            
        elif ospf_header.type == 3:  # Link State Request (LSR)
            print("   - Jenis: Link State Request")
            
            # Proses LSR dan kirim LSU sebagai respon
            
        elif ospf_header.type == 4:  # Link State Update (LSU) 
            print("   - Jenis: Link State Update")
            
            update_lsa(packet)  
    
    return False

def update_lsa(lsu_packet):
    """Memperbarui database link-state berdasarkan LSU"""
    for lsa in lsu_packet[OSPF_LSUpd].lsalist:
        if isinstance(lsa, OSPF_Router_LSA):
           process_router_lsa(lsa)

def process_router_lsa(lsa):
    """Memproses Router LSA"""
    links_info = []
    
    for link in lsa.linklist:
       links_info.append({
           'link_id': link.id,
           'link_data': link.data,
           'type': link.type,
           'metric': link.toscost or link.metric or None 
       })
       
       if hasattr(link, 'toscost'):
          metric_type = "TOS"
       else:
          metric_type = "Standard"
          
       print(f"Link ID:{link.id} | Data:{link.data} | Type:{link.type} | Metric({metric_type}):{links_info[-1]['metric']}")


def start_sniffing():
     """Mulai menangkap paket jaringan"""     
     interface_name = input("Masukkan nama interface jaringan Anda (contoh eth0): ")
     
     try:
         while True:
             sniff(filter="proto ospf", prn=process_ospf_packet, store=False, iface=interface_name)   
             
     except KeyboardInterrupt:
         pass


if __name__ == "__main__":
      start_sniffing()
