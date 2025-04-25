from scapy.all import *
from scapy.contrib.ospf import *
import time

# Konfigurasi parameter OSPF
router_id = "10.10.1.2"  # Router ID
area_id = "0.0.0.0"        # Area ID
interface = "ens5"         # Network interface

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
    router="10.10.1.2",
    backup="0.0.0.0",
    neighbors=[]
)

# Menggabungkan semua layer menjadi satu paket lengkap
ospf_packet = eth / ip / ospf_header / ospf_hello

# Fungsi untuk mengirim paket OSPF Hello setiap 10 detik
def send_ospf_hello_periodically(interval):
    while True:
        sendp(ospf_packet, iface=interface, verbose=1)
        print(f"Sent OSPF Hello packet at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        time.sleep(interval)

# Mengirim paket OSPF Hello setiap 10 detik
send_ospf_hello_periodically(10)
