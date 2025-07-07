import argparse
import os
import sys
import time
import threading
import queue
from scapy.all import Ether, IP, TCP, Raw, sendp, sniff, get_if_hwaddr, getmacbyip, conf

results_queue = queue.Queue()

def send_packet(index, src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload, iface):
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags='S') / Raw(load=payload)
    send_time = time.time()
    sendp(pkt, iface=iface, verbose=0)
    results_queue.put((index, send_time, sport))

def sniff_replies(expected_sports, dst_ip, iface, timeout=5):
    def pkt_filter(pkt):
        return (
            pkt.haslayer(IP) and
            pkt.haslayer(TCP) and
            pkt[IP].src == dst_ip and
            pkt[TCP].flags == 'SA' and
            pkt[TCP].sport == 80 and
            pkt[TCP].dport in expected_sports
        )
    return sniff(iface=iface, timeout=timeout, lfilter=pkt_filter)

def get_gateway_and_iface(target_ip):
    try:
        route_info = conf.route.route(target_ip)
        iface, _, gateway_ip = route_info
        if gateway_ip == '0.0.0.0':
            gateway_ip = target_ip
        return gateway_ip, iface
    except Exception as e:
        sys.exit(f"[!] Tidak bisa resolve route: {e}")

def run_traffic(target_ip, source_ip, count, rps, size):
    print("[*] Setup routing & MAC...")
    gateway, iface = get_gateway_and_iface(target_ip)
    dst_mac = getmacbyip(gateway)
    if not dst_mac:
        dst_mac = "ff:ff:ff:ff:ff:ff"
    src_mac = get_if_hwaddr(iface)

    payload_size = max(0, size - 40)
    payload = b'X' * payload_size

    sent_time_map = {}
    print(f"[+] Mengirim {count} TCP SYN @ {rps} rps ke {target_ip}\n")

    threads = []
    start_time = time.time()
    for i in range(count):
        t = threading.Thread(target=send_packet, args=(i, src_mac, dst_mac, source_ip, target_ip,
                                                       10000 + i, 80, payload, iface))
        t.start()
        threads.append(t)
        time.sleep(1 / rps)

    for t in threads:
        t.join()

    while not results_queue.empty():
        i, t_sent, sport = results_queue.get()
        sent_time_map[sport] = t_sent

    print("[*] Mulai sniff balasan...")
    replies = sniff_replies(set(sent_time_map.keys()), target_ip, iface, timeout=5)

    total_sent = count
    total_received = 0
    total_bytes = 0
    rtts = []

    for pkt in replies:
        sport = pkt[TCP].dport
        recv_time = pkt.time
        if sport in sent_time_map:
            rtt = (recv_time - sent_time_map[sport]) * 1000
            rtts.append(rtt)
            total_bytes += len(pkt)
            total_received += 1

    duration = time.time() - start_time
    avg_rtt = sum(rtts) / len(rtts) if rtts else 0
    throughput = (total_bytes * 8 / 1000) / duration if duration > 0 else 0
    rps_actual = total_received / duration

    print("\n=== HASIL ===")
    print(f"Total Dikirim    : {total_sent}")
    print(f"Total Diterima   : {total_received}")
    print(f"RTT Rata-rata    : {avg_rtt:.2f} ms")
    print(f"Throughput       : {throughput:.2f} Kbps")
    print(f"RPS Aktual       : {rps_actual:.2f} req/s")
    print("=================\n")

def main():
    if os.geteuid() != 0:
        sys.exit("[!] Harus dijalankan sebagai root!")

    parser = argparse.ArgumentParser()
    parser.add_argument('--tujuan', type=str, default="192.168.2.2", help="IP tujuan")
    parser.add_argument('--sumber', type=str, default="192.168.1.3", help="IP sumber")
    parser.add_argument('--jumlah', type=int, required=True, help="Jumlah total paket")
    parser.add_argument('--rps', type=int, required=True, help="Rate per second")
    parser.add_argument('--ukuran', type=int, default=64, help="Ukuran total paket (bytes)")
    args = parser.parse_args()

    run_traffic(args.tujuan, args.sumber, args.jumlah, args.rps, args.ukuran)

if __name__ == '__main__':
    main()
