from scapy.all import *
import datetime

def monitoring_icmp(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:  # ICMP echo request (ping)
        waktu_kirim = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        interface = pkt.sniffed_on if hasattr(pkt, "sniffed_on") else "unknown"
        print(f"[{waktu_kirim}] Paket ICMP keluar ke {pkt[IP].dst} melalui interface {interface}")

# Dapatkan daftar semua interface yang aktif
interfaces = get_if_list()

# Jalankan sniff di semua interface sekaligus
sniff(iface=interfaces, filter="icmp and outbound", prn=monitoring_icmp, store=0)
