from scapy.all import sniff, TCP, ICMP
from datetime import datetime
import threading

def monitor_packet(packet, interface_name):
    waktu = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        print(f"[{waktu}] Paket TCP SYN keluar pada interface {interface_name}: {packet.summary()}")
    elif packet.haslayer(ICMP) and packet[ICMP].type == 8:
        print(f"[{waktu}] Paket ICMP echo request keluar pada interface {interface_name}: {packet.summary()}")

def start_sniff(interface_name):
    print(f"Memulai monitoring pada interface {interface_name}...")
    sniff(iface=interface_name, prn=lambda pkt: monitor_packet(pkt, interface_name), store=0)

interfaces = ['ens5', 'ens6', 'ens7']

threads = []
for iface in interfaces:
    t = threading.Thread(target=start_sniff, args=(iface,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()
