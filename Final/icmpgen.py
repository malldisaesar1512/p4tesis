from scapy.all import *
import time

def icmp_ping(src_mac, dst_mac, src_ip, dst_ip, count):
    print("Sending ICMP ping...")
    for i in range(count):
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / ICMP()
        resp = srp1(pkt, timeout=2, verbose=0)
        if resp:
            rtt = (resp.time - pkt.sent_time) * 1000  # RTT dalam ms
            print(f"ICMP Ping {i+1}: RTT = {rtt:.2f} ms")
        else:
            print(f"ICMP Ping {i+1}: Request timed out")

if __name__ == "__main__":
    src_mac = "50:00:00:00:10:00"
    dst_mac = "50:00:00:00:00:00"
    src_ip = "192.168.1.3"
    dst_ip = "192.168.2.2"

    count = int(input("Enter number of ICMP pings to send: "))
    icmp_ping(src_mac, dst_mac, src_ip, dst_ip, count)
