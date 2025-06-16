from scapy.all import *
import time
from datetime import datetime

def icmp_ping(src_mac, dst_mac, src_ip, dst_ip, count):
    print("Sending ICMP ping...")
    for i in range(count):
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / ICMP()
        resp = srp1(pkt, timeout=2, verbose=0)
        now = datetime.now()
        timestamp = now.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]  # Milliseconds precision
        if resp:
            if resp.time and pkt.sent_time:
                rtt = (resp.time - pkt.sent_time) * 1000  # RTT in ms
                print(f"ICMP Ping {i+1}: RTT = {rtt:.2f} ms at {timestamp}")
            else:
                print(f"ICMP Ping {i+1}: Response received but timing unavailable at {timestamp}")
        else:
            print(f"ICMP Ping {i+1}: Request timed out at {timestamp}")
        time.sleep(1)

if __name__ == "__main__":
    src_mac = "50:00:00:00:10:00"
    dst_mac = "50:00:00:00:60:00"
    src_ip = "192.168.1.3"
    dst_ip = "192.168.2.2"

    count = int(input("Enter number of ICMP pings to send: "))
    icmp_ping(src_mac, dst_mac, src_ip, dst_ip, count)

