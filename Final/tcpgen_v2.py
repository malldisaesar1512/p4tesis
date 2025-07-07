#!/usr/bin/env python3
import argparse
import time
import os
import sys
import queue
from concurrent.futures import ThreadPoolExecutor
from scapy.all import (
    Ether,
    IP,
    TCP,
    Raw,
    srp1,
    conf,
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
        reply = srp1(packet, timeout=1, verbose=0, iface=iface)
        rtt = (time.time() - send_time) * 1000  # dalam ms
        bytes_sent = len(packet)

        if reply is None:
            results_queue.put(('FAILURE', 0, bytes_sent))
            return

        results_queue.put(('SUCCESS', rtt, bytes_sent))

    except Exception:
        results_queue.put(('FAILURE', 0, 0))

def get_gateway_and_iface(target_ip):
    try:
        route_info = conf.route.route(target_ip)
        iface, _, gateway_ip = route_info
        if gateway_ip == '0.0.0.0':
            gateway_ip = target_ip
        return gateway_ip, iface
    except Exception as e:
        sys.exit(f"[!] Error: Tidak dapat menemukan rute ke {target_ip}. Detail: {e}")

def format_bytes_to_kbps(byte_count, duration_secs):
    if duration_secs == 0: return 0
    return ((byte_count * 8) / 1000) / duration_secs

def tcp_traffic_generator(target_ip, source_ip, count, rps, size):
    print("--- Mengkonfigurasi Jaringan Secara Otomatis ---")
    gateway_ip, iface = get_gateway_and_iface(target_ip)
    dst_mac = getmacbyip(gateway_ip)

    if not dst_mac:
        print("[!] Warning: Gagal mendapatkan MAC dari gateway, mencoba fallback ARP request manual...")
        dst_mac = "ff:ff:ff:ff:ff:ff"  # fallback broadcast

    src_mac = get_if_hwaddr(iface)
    print(f"[*] Interface: {iface}, Gateway: {gateway_ip}, MAC Tujuan: {dst_mac}")
    print("--- Konfigurasi Selesai ---\n")

    results_queue = queue.Queue()
    rtt_list = []
    total_bytes_sent = 0
    successful_pings = 0
    failed_pings = 0
    
    payload_size = max(0, size - 40)
    payload = b'P' * payload_size
    max_workers = min(1000, rps * 2)

    print(f"Memulai pengiriman {count} paket ke {target_ip} dengan target {rps} RPS...")

    overall_start_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="pkt") as executor:
        dispatch_start_time = time.perf_counter()

        for i in range(count):
            expected_dispatch_time = dispatch_start_time + (i / rps)
            sleep_duration = expected_dispatch_time - time.perf_counter()
            if sleep_duration > 0:
                time.sleep(sleep_duration)
            
            sport = 1024 + (i % 64511)
            executor.submit(send_and_receive_worker, results_queue, src_mac, dst_mac, source_ip, target_ip, sport, 80, payload, iface)

        print("\nSemua tugas telah dikirim. Mengumpulkan hasil...")

        timeout_global = count * 0.005 + 10  # total timeout = 5 ms per paket + 10 detik ekstra
        wait_start = time.time()
        for i in range(count):
            try:
                remain_timeout = max(0.1, timeout_global - (time.time() - wait_start))
                status, rtt, bytes_sent = results_queue.get(timeout=remain_timeout)
                total_bytes_sent += bytes_sent
                if status == 'SUCCESS':
                    successful_pings += 1
                    rtt_list.append(rtt)
                else:
                    failed_pings += 1
            except queue.Empty:
                print(f"\n[!] Timeout menunggu hasil dari thread ke-{i+1}")
                failed_pings += 1
            
            print(f"\rProgress: {i+1}/{count} hasil diproses...", end="")

    print("\n\nProses pengumpulan hasil selesai.")
    overall_end_time = time.perf_counter()
    total_duration = overall_end_time - overall_start_time

    avg_rtt = sum(rtt_list) / len(rtt_list) if rtt_list else 0
    throughput_kbps = format_bytes_to_kbps(total_bytes_sent, total_duration)
    actual_rps = successful_pings / total_duration if total_duration > 0 else 0

    print("="*20 + " HASIL AKHIR " + "="*20)
    print(f"Waktu Total             : {total_duration:.2f} detik")
    print(f"Paket Dijadwalkan       : {count}")
    print(f"Balasan Diterima (Sukses): {successful_pings}")
    print(f"Gagal/Timeout/Macet     : {failed_pings}")
    print(f"Rata-rata RTT           : {avg_rtt:.2f} ms")
    print(f"Throughput              : {throughput_kbps:.2f} Kbps")
    print(f"RPS Aktual (tercapai)   : {actual_rps:.2f} req/detik")
    print("=" * 51)

def main():
    if os.geteuid() != 0:
        sys.exit("[!] Error: Jalankan dengan hak akses root/administrator (gunakan 'sudo').")

    parser = argparse.ArgumentParser(description="Traffic Generator TCP Multi-Threaded (Anti-Hang Optimized).")
    parser.add_argument('--tujuan', type=str, default="192.168.2.2", help="Alamat IP tujuan.")
    parser.add_argument('--sumber', type=str, default="192.168.1.3", help="Alamat IP sumber.")
    parser.add_argument('--jumlah', type=int, required=True, help="Jumlah total paket.")
    parser.add_argument('--rps', type=int, required=True, help="Target paket per detik.")
    parser.add_argument('--ukuran', type=int, default=64, help="Ukuran total paket dalam bytes.")
    args = parser.parse_args()

    tcp_traffic_generator(args.tujuan, args.sumber, args.jumlah, args.rps, args.ukuran)

if __name__ == "__main__":
    main()
