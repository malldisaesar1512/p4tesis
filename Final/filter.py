from scapy.all import sniff, TCP, ICMP
from datetime import datetime
import threading

def monitor_packet(packet):
    waktu = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # waktu dengan ms
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        print(f"[{waktu}] Paket TCP SYN keluar: {packet.summary()}")
    elif packet.haslayer(ICMP) and packet[ICMP].type == 8:
        print(f"[{waktu}] Paket ICMP echo request keluar: {packet.summary()}")

def start_sniff(interface_name):
    print(f"Memulai monitoring pada interface {interface_name}...")
    sniff(iface=interface_name, prn=monitor_packet, store=0, direction="out")

# Daftar interface yang ingin dipantau
interfaces = ['ens5', 'ens6', 'ens7']  # ubah sesuai dengan interface Anda

# Buat thread untuk setiap interface agar berjalan bersamaan
threads = []
for iface in interfaces:
    t = threading.Thread(target=start_sniff, args=(iface,))
    t.start()
    threads.append(t)

# Tunggu hingga semua thread selesai (normalnya berlangsung terus sampai dihentikan manual)
for t in threads:
    t.join()
