from scapy.all import sniff, TCP, ICMP, get_if_hwaddr
from datetime import datetime
import threading

def monitor_packet(packet, iface_mac):
    waktu = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    # Filter paket yang keluar berdasarkan source MAC dari interface
    if not packet.haslayer('Ether'):
        return

    # Pastikan paket keluar dari interface ini (source MAC sama dengan MAC iface)
    if packet.src != iface_mac:
        return

    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        print(f"[{waktu}] Paket TCP SYN keluar pada interface: {packet.summary()}")
    elif packet.haslayer(ICMP) and packet[ICMP].type == 8:
        print(f"[{waktu}] Paket ICMP echo request keluar pada interface: {packet.summary()}")

def start_sniff(interface_name):
    print(f"Memulai monitoring pada interface {interface_name}...")
    iface_mac = get_if_hwaddr(interface_name)
    sniff(iface=interface_name, prn=lambda pkt: monitor_packet(pkt, iface_mac), store=0)

interfaces = ['ens5', 'ens6', 'ens7']  # ganti dengan interface yang ingin dipantau

threads = []
for iface in interfaces:
    t = threading.Thread(target=start_sniff, args=(iface,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()
