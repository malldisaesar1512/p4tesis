from scapy.all import *
import time

def custom_tcp_ping(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count):
    for i in range(count):
        # Membuat paket TCP SYN dengan layer Ethernet dan IP sesuai format
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S')

        # Mengirim paket dan mengukur RTT
        start_time = time.time()
        resp = srp1(pkt, timeout=2, verbose=0)
        end_time = time.time()

        if resp is None:
            print(f"Request timed out for ping {i+1}")
        else:
            rtt = (end_time - start_time) * 1000  # RTT dalam ms
            print(f"Ping {i+1}: RTT = {rtt:.2f} ms")

if __name__ == "__main__":
    # Contoh nilai dari gambar dan input
    src_mac = "50:00:00:00:10:00"
    dst_mac = "50:00:00:00:60:00"
    src_ip = "192.168.1.3"
    dst_ip = "192.168.2.2"
    src_port = 12345
    dst_port = 80

    count = int(input("Enter number of TCP pings to send: "))
    custom_tcp_ping(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count)
