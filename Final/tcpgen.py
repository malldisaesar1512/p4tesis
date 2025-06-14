from scapy.all import *
import time

def tcp_ping(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count):
    print("Sending TCP SYN ping...")
    for i in range(count):
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S')
        resp = srp1(pkt, timeout=2, verbose=0)
        if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:  # SYN-ACK diterima
            rtt = (resp.time - pkt.sent_time) * 1000  # RTT dalam ms
            print(f"TCP Ping {i+1}: RTT = {rtt:.2f} ms")
            # Kirim RST untuk menutup koneksi dengan sopan
            sendp(Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="R"), verbose=0)
        else:
            print(f"TCP Ping {i+1}: Request timed out or no SYN-ACK received")

if __name__ == "__main__":
    src_mac = "50:00:00:00:10:00"
    dst_mac = "50:00:00:00:60:00"
    src_ip = "192.168.1.3"
    dst_ip = "192.168.2.2"
    src_port = 12345
    dst_port = 80

    count = int(input("Enter number of TCP pings to send: "))
    tcp_ping(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count)
