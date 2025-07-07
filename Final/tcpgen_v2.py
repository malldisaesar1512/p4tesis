import argparse
import time
import os
import sys
import queue
from concurrent.futures import ThreadPoolExecutor
from scapy.all import (
    Ether, IP, TCP, Raw,
    srp1, conf,
    get_if_hwaddr,
    getmacbyip
)

def send_and_receive_worker(results_queue, src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload, iface):
    try:
        packet = (
            Ether(src=src_mac, dst=dst_mac) /
            IP(src=src_ip, dst=dst_ip) /
            TCP(sport=sport, dport=dport, flags='S') /
            Raw(load=payload)
        )

        send_time = time.time()
        reply = srp1(packet, timeout=0.5, verbose=0, iface=iface)
        rtt = (time.time() - send_time) * 1000  # ms
        bytes_sent = len(packet)

        if reply:
            results_queue.put(('SUCCESS', rtt, bytes_sent))
        else:
            results_queue.put(('FAILURE', 0, bytes_sent))

    except Exception as e:
        results_queue.put(('FAILURE', 0, 0))

def get_gateway_and_iface(target_ip):
    try:
        route_info = conf.route.route(target_ip)
        iface, _, gateway_ip = route_info
        if gateway_ip == '0.0.0.0':
            gateway_ip = target_ip
        return gateway_ip, iface
    except Exception as e:
        sys.exit(f"[!] Tidak dapat menemukan rute ke {target_ip}: {e}")

def format_bytes_to_kbps(byte_count, duration_secs):
    if duration_secs == 0: return 0
    return ((byte_count * 8) / 1000) / duration_secs

def tcp_traffic_generator(target_ip, source_ip, count, rps, size):
    print("[*] Auto-Konfigurasi jaringan...")
    gateway_ip, iface = get_gateway_and_iface(target_ip)
    dst_mac = getmacbyip(gateway_ip)
    if not dst_mac:
        print("[!] MAC gateway tidak ditemukan, fallback broadcast.")
        dst_mac = "ff:ff:ff:ff:ff:ff"

    src_mac = get_if_hwaddr(iface)
    print(f"[+] Interface: {iface}, Gateway: {gateway_ip}, MAC: {dst_mac}")

    results_queue = queue.Queue()
    rtt_list = []
    total_bytes_sent = 0
    success = 0
    fail = 0

    payload_size = max(0, size - 40)
    payload = b'X' * payload_size
    max_workers = min(500, rps * 2)

    print(f"[+] Kirim {count} paket @ {rps} RPS...")

    start_time = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        dispatch_start = time.perf_counter()
        for i in range(count):
            target_time = dispatch_start + (i / rps)
            delay = target_time - time.perf_counter()
            if delay > 0:
                time.sleep(delay)

            sport = 1024 + (i % 60000)
            executor.submit(send_and_receive_worker, results_queue, src_mac, dst_mac,
                            source_ip, target_ip, sport, 80, payload, iface)

    print("[*] Semua request dikirim. Mengumpulkan hasil...\n")

    timeout_global = time.time() + 10  # batas pengumpulan 10 detik
    for i in range(count):
        try:
            remain = max(0.1, timeout_global - time.time())
            status, rtt, bytes_sent = results_queue.get(timeout=remain)
            total_bytes_sent += bytes_sent
            if status == 'SUCCESS':
                success += 1
                rtt_list.append(rtt)
            else:
                fail += 1
        except queue.Empty:
            print(f"[!] Timeout hasil ke-{i+1}, dianggap gagal.")
            fail += 1
        print(f"\rProgress: {i+1}/{count}", end='')

    end_time = time.perf_counter()
    duration = end_time - start_time
    avg_rtt = sum(rtt_list) / len(rtt_list) if rtt_list else 0
    throughput = format_bytes_to_kbps(total_bytes_sent, duration)
    rps_actual = success / duration if duration > 0 else 0

    print("\n\n====== HASIL ======")
    print(f"Durasi Total     : {duration:.2f} detik")
    print(f"Total Dikirim    : {count}")
    print(f"Sukses           : {success}")
    print(f"Gagal/Timeout    : {fail}")
    print(f"RTT Rata-rata    : {avg_rtt:.2f} ms")
    print(f"Throughput       : {throughput:.2f} Kbps")
    print(f"RPS Aktual       : {rps_actual:.2f} req/s")
    print("====================")

def main():
    if os.geteuid() != 0:
        sys.exit("[!] Harus dijalankan sebagai root!")

    parser = argparse.ArgumentParser()
    parser.add_argument('--tujuan', type=str, default="192.168.2.2", help="IP tujuan")
    parser.add_argument('--sumber', type=str, default="192.168.1.3", help="IP sumber")
    parser.add_argument('--jumlah', type=int, required=True, help="Jumlah paket total")
    parser.add_argument('--rps', type=int, required=True, help="Rate per second")
    parser.add_argument('--ukuran', type=int, default=64, help="Ukuran total paket (bytes)")
    args = parser.parse_args()

    tcp_traffic_generator(args.tujuan, args.sumber, args.jumlah, args.rps, args.ukuran)

if __name__ == "__main__":
    main()
