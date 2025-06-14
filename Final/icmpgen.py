from scapy.all import *
import time

def custom_ping(src_mac, dst_mac, src_ip, dst_ip, count):
    for i in range(count):
        # Build the packet based on user requirements and image format
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / ICMP()

        # Send the packet and measure RTT
        start_time = time.time()
        resp = srp1(pkt, timeout=2, verbose=0)
        end_time = time.time()

        if resp is None:
            print(f"Request timed out for ping {i+1}")
        else:
            rtt = (end_time - start_time) * 1000  # RTT in milliseconds
            print(f"Ping {i+1}: RTT = {rtt:.2f} ms")

if __name__ == "__main__":
    # Example values from the image and prompt
    src_mac = "50:00:00:00:10:00"
    dst_mac = "50:00:00:00:60:00"
    src_ip = "192.168.1.3"
    dst_ip = "192.168.2.2"

    count = int(input("Enter number of pings to send: "))
    custom_ping(src_mac, dst_mac, src_ip, dst_ip, count)
