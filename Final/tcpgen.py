from scapy.all import *
import time

def custom_tcp_ping(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count):
    for i in range(count):
        # Membuat paket TCP SYN dengan layer Ethernet dan IP sesuai format
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S')

        # Mengirim paket dan mengukur RTT
        resp = srp1(pkt, timeout=2, verbose=0)

        if resp is None:
            print(f"Request timed out for ping {i+1}")
        else:
            rtt = (resp.time - pkt.sent_time) * 1000  # RTT dalam ms
            print(f"Ping {i+1}: RTT = {rtt:.2f} ms")
        time.sleep(1)

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
