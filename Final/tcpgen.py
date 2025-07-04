from scapy.all import *
import time

MTU = 1500
IP_HEADER_SIZE = 20
TCP_HEADER_SIZE = 20
MAX_FRAGMENT_SIZE = MTU - IP_HEADER_SIZE  # Fragment size untuk IP layer (payload di IP layer)

def custom_tcp_ping_fragmented(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count, rps=1, size=2000):
    interval = 1.0 / rps
    
    total_bytes_sent = 0
    start_time = time.time()
    
    payload = b'X' * size  # payload sesuai size diminta
    
    for i in range(count):
        # Buat paket TCP SYN tanpa payload dulu (header saja)
        base_pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S')
        
        # Gabungkan header TCP + payload sebagai data load IP, nanti di-fragment
        # Buat paket IP terpisah dengan layer TCP+payload sebagai Raw, fragmentasi di level IP saja
        ip_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S') / Raw(payload)
        
        # Fragmentasi paket IP ini (frag size MAX_FRAGMENT_SIZE)
        frags = fragment(ip_pkt, fragsize=MAX_FRAGMENT_SIZE)
        
        # Kirim setiap fragmen dengan layer Ethernet
        for idx, frag in enumerate(frags):
            ether_frag = Ether(src=src_mac, dst=dst_mac) / frag
            sendp(ether_frag, verbose=0)
            total_bytes_sent += len(ether_frag)
            # print(f"Sent fragment {idx+1} of size {len(ether_frag)} bytes")
        
        # Cek respons hanya untuk fragmen pertama saja dengan srp1
        first_frag_pkt = Ether(src=src_mac, dst=dst_mac) / frags[0]
        resp = srp1(first_frag_pkt, timeout=2, verbose=0)
        
        if resp is None:
            print(f"Request timed out for ping {i+1} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            rtt = (resp.time - first_frag_pkt.sent_time) * 1000  # RTT dalam ms
            print(f"Ping {i+1}: RTT = {rtt:.2f} ms at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        time.sleep(interval)
    
    end_time = time.time()
    duration = end_time - start_time
    throughput_bps = (total_bytes_sent * 8) / duration  # bits per second
    throughput_kbps = throughput_bps / 1000
    
    print(f"\nTotal bytes sent: {total_bytes_sent} bytes")
    print(f"Total duration: {duration:.2f} seconds")
    print(f"Average throughput: {throughput_kbps:.2f} Kbps")

if __name__ == "__main__":
    src_mac = "50:00:00:00:10:00"
    dst_mac = "50:00:00:00:60:00"
    src_ip = "192.168.1.3"
    dst_ip = "192.168.2.2"
    src_port = 12345
    dst_port = 8000

    count = int(input("Enter number of TCP pings to send: "))
    rps = float(input("Enter requests per second: "))
    size = int(input(f"Enter packet size in bytes (can be more than MTU {MTU}): "))

    custom_tcp_ping_fragmented(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count, rps, size)
