from scapy.all import *
import time

def custom_tcp_ping(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count, rps=1, size=40):
    interval = 1.0 / rps
    payload = b'X' * size  # Ukuran payload bytes sebesar parameter size
    
    for i in range(count):
        # Membuat paket TCP SYN dengan layer Ethernet, IP, dan payload sesuai ukuran
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S') / Raw(load=payload)

        # Mengirim paket dan mengukur RTT
        resp = srp1(pkt, timeout=2, verbose=0)

        if resp is None:
            print(f"Request timed out for ping {i+1} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            rtt = (resp.time - pkt.sent_time) * 1000  # RTT dalam ms
            print(f"Ping {i+1}: RTT = {rtt:.2f} ms at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        time.sleep(interval)  # Jeda sesuai rata-rata paket per detik

if __name__ == "__main__":
    src_mac = "50:00:00:00:10:00"
    dst_mac = "50:00:00:00:60:00"
    src_ip = "192.168.1.3"
    dst_ip = "192.168.2.2"
    src_port = 12345
    dst_port = 80

    count = int(input("Enter number of TCP pings to send: "))
    rps = float(input("Enter requests per second: "))
    size = int(input("Enter packet size in bytes: "))

    custom_tcp_ping(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count, rps, size)
