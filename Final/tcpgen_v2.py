#!/usr/bin/env python3
import argparse
import time
import os
import sys
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

def get_gateway_and_iface(target_ip):
    """Mencari tahu gateway dan interface yang benar untuk mencapai target."""
    try:
        # Menggunakan tabel routing Scapy untuk menemukan rute ke target
        route_info = conf.route.route(target_ip)
        iface = route_info[0]
        gateway_ip = route_info[2]
        # Jika target di jaringan lokal, gateway adalah target itu sendiri
        if gateway_ip == '0.0.0.0':
            gateway_ip = target_ip
        return gateway_ip, iface
    except Exception as e:
        print(f"[!] Error: Tidak dapat menemukan rute ke {target_ip}.")
        print(f"    Pastikan Anda memiliki konektivitas jaringan. Detail: {e}")
        sys.exit(1)

def format_bytes_to_kbps(byte_count, duration_secs):
    """Mengonversi total byte dan durasi ke kilobits per second (Kbps)."""
    if duration_secs == 0:
        return 0
    bits = byte_count * 8
    kbps = (bits / 1000) / duration_secs
    return kbps

def tcp_traffic_generator(target_ip, source_ip, count, rps, size):
    """Fungsi utama untuk membuat dan mengirim traffic TCP."""
    
    print("--- Mengkonfigurasi Jaringan Secara Otomatis ---")
    
    # 1. Temukan gateway dan interface yang benar secara dinamis
    gateway_ip, iface = get_gateway_and_iface(target_ip)
    print(f"[*] Interface yang akan digunakan: {iface}")
    print(f"[*] Gateway atau hop selanjutnya: {gateway_ip}")

    # 2. Dapatkan alamat MAC dari gateway (atau host tujuan jika di jaringan lokal)
    dst_mac = getmacbyip(gateway_ip)
    if not dst_mac:
        print(f"[!] Error: Gagal mendapatkan alamat MAC untuk {gateway_ip}. Cek konektivitas.")
        sys.exit(1)
    print(f"[*] Alamat MAC tujuan (Gateway/Host): {dst_mac}")

    # 3. Dapatkan alamat MAC dari interface sumber kita
    src_mac = get_if_hwaddr(iface)
    print(f"[*] Alamat MAC sumber: {src_mac}")
    print("--- Konfigurasi Selesai ---\n")

    rtt_list = []
    successful_pings = 0
    total_bytes_sent = 0
    
    # Port sumber akan diinkrementasi agar setiap koneksi unik
    current_sport = 1024 
    
    # Ukuran payload dikurangi header (IP:20, TCP:20)
    payload_size = max(0, size - 40)
    payload = b'P' * payload_size

    interval = 1.0 / rps

    print(f"Memulai pengiriman {count} paket TCP SYN ke {target_ip} dengan rate {rps} RPS...")
    
    overall_start_time = time.perf_counter()

    for i in range(count):
        dispatch_time = overall_start_time + (i * interval)
        sleep_duration = dispatch_time - time.perf_counter()
        if sleep_duration > 0:
            time.sleep(sleep_duration)

        current_sport += 1
        
        # Membuat paket lengkap dari Layer 2 hingga Layer 4
        packet = (
            Ether(src=src_mac, dst=dst_mac) /
            IP(src=source_ip, dst=target_ip) /
            TCP(sport=current_sport, dport=80, flags='S') /
            Raw(load=payload)
        )
        
        # Mengirim paket dan menunggu 1 balasan
        reply = srp1(packet, timeout=2, verbose=0, iface=iface)
        
        total_bytes_sent += len(packet)

        if reply is None:
            print(f"Ping {i+1}/{count}: Request Timed Out (RTO)")
        else:
            successful_pings += 1
            # Menghitung RTT dari waktu kirim dan terima
            rtt = (reply.time - packet.sent_time) * 1000  # dalam milidetik
            rtt_list.append(rtt)
            # Menampilkan flag balasan (misal: SA untuk SYN-ACK)
            tcp_flags = reply.getlayer(TCP).flags
            print(f"Ping {i+1}/{count}: Diterima balasan dari {reply[IP].src} | RTT: {rtt:.2f} ms | Flags: {tcp_flags}")

    overall_end_time = time.perf_counter()
    total_duration = overall_end_time - overall_start_time
    
    avg_rtt = sum(rtt_list) / len(rtt_list) if rtt_list else 0
    throughput_kbps = format_bytes_to_kbps(total_bytes_sent, total_duration)

    print("\n" + "="*20 + " HASIL AKHIR " + "="*20)
    print(f"Total Waktu             : {total_duration:.2f} detik")
    print(f"Paket Terkirim          : {count}")
    print(f"Balasan Diterima        : {successful_pings}")
    print(f"Rata-rata RTT           : {avg_rtt:.2f} ms")
    print(f"Total Data Terkirim     : {total_bytes_sent} bytes")
    print(f"Throughput              : {throughput_kbps:.2f} Kbps")
    print("=" * 51)


def main():
    # Cek hak akses root/administrator
    if os.geteuid() != 0:
        print("[!] Error: Skrip ini membutuhkan hak akses root/administrator untuk dijalankan.")
        print("    Silakan coba lagi dengan 'sudo python nama_skrip.py'")
        sys.exit(1)
        
    parser = argparse.ArgumentParser(
        description="Traffic Generator TCP dengan deteksi rute dan MAC otomatis.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--tujuan', type=str, default="192.168.2.2", help="Alamat IP tujuan.")
    parser.add_argument('--sumber', type=str, default="192.168.1.3", help="Alamat IP sumber.")
    parser.add_argument('--jumlah', type=int, required=True, help="Jumlah total paket yang akan dikirim.")
    parser.add_argument('--rps', type=int, required=True, help="Target paket per detik (requests per second).")
    parser.add_argument('--ukuran', type=int, default=64, help="Ukuran total paket dalam bytes (termasuk header).")
    args = parser.parse_args()

    tcp_traffic_generator(args.tujuan, args.sumber, args.jumlah, args.rps, args.ukuran)

if __name__ == "__main__":
    main()