from scapy.all import *
from scapy.contrib.ospf import *
import time

# Konfigurasi parameter OSPF
router_id = "10.10.1.2"  # Router ID
router_id2 = "192.168.1.1" # Router ID 2
area_id = "0.0.0.0"        # Area ID
interface = "ens5"         # Network interface
neighbor_state = "Init"
neighbor_ip = "10.10.1.1"

# Membuat paket Ethernet
eth = Ether()

# Membuat paket IP dengan destination multicast address OSPF (224.0.0.5)
ip = IP(src=router_id, dst="224.0.0.5")

# Membuat header OSPF (versi 2, tipe 1=Hello)
ospf_header = OSPF_Hdr(version=2, type=1, src=router_id, area=area_id)

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

# Menggabungkan semua layer menjadi satu paket lengkap
ospf_packet = eth / ip / ospf_header / ospf_hello

# Fungsi untuk mengirim paket OSPF Hello setiap 10 detik
def send_ospf_hello_periodically(interval):
    global neighbor_state
    while True:
        if neighbor_state == "Init":
            ospf_hello.neighbors = []
        elif neighbor_state == "2-Way":
            ospf_hello.neighbors = [neighbor_ip]
        sendp(ospf_packet, iface=interface, verbose=0)
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

def send_ospf_dbd(neighbor_router_ip):
    """Kirim paket Database Description (DBD) ke neighbor"""
    
    # Header IP unicast ke neighbor router IP (asumsi router_ip adalah alamat source dari neighbor)
    ip_dbd = IP(src=router_id, dst=str(neighbor_router_ip))
    
    # Header OSPF tipe 2: Database Description Packet 
    ospf_hdr_dbd = OSPF_Hdr(version=2, type=2, src=router_id, area=area_id)
    
    # Buat DBD packet dengan flag Init bit set (bit kedua), seq number awal misal 1.
    
    ospf_dbd_pkt = (
        eth /
        ip_dbd /
        ospf_hdr_dbd /
        OSPF_DBDesc(
            options=0x02,
            mtu=1500,
            dbdescr=["I","M","MS"],   # 'I' berarti Init bit set; bisa juga angka: flags=(1 << 1) == 2 
            ddseq=random.randint(10000,50000)
        ) /
        OSPF_LSA_Hdr(
            age=360,
            options=0x02,
            type=1,  # Router LSA
            id=router_id,
            adrouter=router_id,
            seq=0x80000123  # Sequence number
        ) /
        OSPF_LSA_Hdr(
            age=360,
            options=0x02,
            type=1,  # Network LSA
            id=router_id2,
            adrouter=router_id2,
            seq=0x80000124  # Sequence number
        ) /
        OSPF_LSA_Hdr(
            age=360,
            options=0x02,
            type=2,  # Summary LSA
            id=router_id2,
            adrouter=router_id,
            seq=0x80000125  # Sequence number
        )
     )
    
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Sending DBD packet to {neighbor_router_ip}")
    sendp(ospf_dbd_pkt , iface=interface , verbose=True)


def handle_incoming_packet(packet):
   global neighbor_state

   if not packet.haslayer(OSPF_Hdr):
       return
   
   ospfhdr_layer = packet.getlayer(OSPF_Hdr)
   
   if ospfhdr_layer.type == 1: # Hello Packet
       # Paket hello diterima -> kirim DBD sebagai respons ke source IP di layer IP 
       src_ip_of_neighbor = packet[IP].src
    #    ospf_hello.neighbors = src_ip_of_neighbor  # Simpan neighbor router IP
       print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received HELLO from {src_ip_of_neighbor}, sending DBD...")
       if neighbor_state == "Init":
            neighbor_state = "2-Way"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Received HELLO from {src_ip_of_neighbor}, moving to 2-Way")
            ospf_hello.neighbors = [src_ip_of_neighbor]
    #    try:
    #        send_ospf_2way()           # Kirim DBD ke neighbor router IP
    #        send_ospf_dbd(src_ip_of_neighbor)
    #    except Exception as e:
    #        print(f"Error sending DBD: {e}")

def sniff_packets():
   sniff(iface=interface , filter="ip proto ospf", prn=lambda pkt: handle_incoming_packet(pkt), store=False)


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
