from scapy.all import *
import time
from datetime import datetime

def icmp_ping(src_mac, dst_mac, src_ip, dst_ip, count, requests_per_second=1, packet_size_bytes=64):
    print("Sending ICMP ping...")
    rtts = []
    # Minimal ukuran paket ICMP header agar tidak error saat menambahkan payload
    min_icmp_header_size = 8  # Bytes for ICMP header
    
    # Hitung berapa byte payload yang dibutuhkan agar total paket sesuai ukuran yang diminta
    # Header IP dan Ethernet tidak kita hitung, fokus payload ICMP saja
    if packet_size_bytes < min_icmp_header_size:
        print(f"Packet size too small, setting to minimum {min_icmp_header_size} bytes")
        packet_size_bytes = min_icmp_header_size
    
    payload_size = packet_size_bytes - min_icmp_header_size
    payload = b'\x00' * payload_size  # Payload kosong sesuai ukuran
    
    delay = 1 / requests_per_second  # interval antar ping dalam detik

    for i in range(count):
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / ICMP() / Raw(load=payload)
        resp = srp1(pkt, timeout=2, verbose=0)
        now = datetime.now()
        timestamp = now.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        if resp:
            if resp.time and pkt.sent_time:
                rtt = (resp.time - pkt.sent_time) * 1000  # RTT in ms
                rtts.append(rtt)
                print(f"ICMP Ping {i+1}: RTT = {rtt:.2f} ms at {timestamp}")
            else:
                print(f"ICMP Ping {i+1}: Response received but timing unavailable at {timestamp}")
        else:
            print(f"ICMP Ping {i+1}: Request timed out at {timestamp}")

        time.sleep(delay)

    if rtts:
        avg_rtt = sum(rtts) / len(rtts)
        throughput_bps = (packet_size_bytes * 8) / (avg_rtt / 1000)  # bits per second
        print(f"\nAverage RTT: {avg_rtt:.2f} ms")
        print(f"Estimated Throughput: {throughput_bps:.2f} bits/second")
    else:
        print("\nNo successful pings to compute average RTT and throughput.")

if __name__ == "__main__":
    src_mac = "50:00:00:00:10:00"
    dst_mac = "50:00:00:00:60:00"
    src_ip = "192.168.1.3"
    dst_ip = "192.168.2.2"

    count = int(input("Enter number of ICMP pings to send: "))
    rps = float(input("Enter requests per second (e.g., 1, 2, 5): "))
    pkt_size = int(input("Enter packet size in bytes (minimum 8): "))
    icmp_ping(src_mac, dst_mac, src_ip, dst_ip, count, requests_per_second=rps, packet_size_bytes=pkt_size)
