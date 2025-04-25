from Final.ospfrouting import HELLO_INTERVAL
from scapy.all import *
from scapy.contrib.ospf import *

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
    HELLO_INTERVAL=10,
    options=0x02,
    priority=128,
    deadinterval=40,
    router="10.10.1.2",
    backup="0.0.0.0",
    neighbors=[]
)

# Menggabungkan semua layer menjadi satu paket lengkap
ospf_packet = eth / ip / ospf_header / ospf_hello

# Mengirimkan paket menggunakan sendp() pada interface yang ditentukan
sendp(ospf_packet, iface=interface, verbose=1)
