from scapy.all import *
import time

MTU = 1500
IP_HEADER_SIZE = 20
MAX_FRAGMENT_SIZE = MTU - IP_HEADER_SIZE

def custom_tcp_ping_fragmented(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count, rps=1, size=2000):
    interval = 1.0 / rps
    
    total_bytes_sent = 0
    start_time = time.time()
    
    payload = b'X' * size
    
    # Port sumber awal yang akan kita ubah-ubah
    current_src_port = src_port

    for i in range(count):
        # PENTING: Membuat "label" koneksi unik agar tidak dianggap retransmisi
        # Dengan menaikkan port sumber, server akan melihat ini sebagai koneksi baru.
        current_src_port += 1
        
        # Membuat paket besar dengan port sumber yang sudah diperbarui
        ip_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=current_src_port, dport=dst_port, flags='S') / Raw(payload)
        
        # Fragmentasi paket
        frags = fragment(ip_pkt, fragsize=MAX_FRAGMENT_SIZE)
        
        # Bungkus fragmen dengan header Ethernet
        ether_frags = [Ether(src=src_mac, dst=dst_mac) / f for f in frags]
        
        # Hitung total byte yang akan dikirim untuk statistik
        for pkt in ether_frags:
            total_bytes_sent += len(pkt)

        # Mengirim semua fragmen dan menunggu jawaban dalam satu operasi
        ans, unans = srp(ether_frags, timeout=2, verbose=0)
        
        if not ans:
            print(f"Request timed out for ping {i+1} (port {current_src_port})")
        else:
            sent_pkt = ans[0][0]
            rcv_pkt = ans[0][1]
            rtt = (rcv_pkt.time - sent_pkt.sent_time) * 1000
            print(f"Ping {i+1} (port {current_src_port}): RTT = {rtt:.2f} ms from {rcv_pkt[IP].src}")
        
        time.sleep(interval)
    
    end_time = time.time()
    duration = end_time - start_time
    throughput_bps = (total_bytes_sent * 8) / duration if duration > 0 else 0
    throughput_kbps = throughput_bps / 1000
    
    print(f"\nTotal bytes sent: {total_bytes_sent} bytes")
    print(f"Total duration: {duration:.2f} seconds")
    print(f"Average throughput: {throughput_kbps:.2f} Kbps")

if __name__ == "__main__":
    src_mac = "50:00:00:00:10:00"
    dst_mac = "50:00:00:00:60:00"
    src_ip = "192.168.1.3"
    dst_ip = "192.168.2.2"
    # Port ini hanya sebagai titik awal
    src_port = RandShort() # Gunakan port acak sebagai titik awal
    dst_port = 80

    count = int(input("Enter number of TCP pings to send: "))
    rps = float(input("Enter requests per second: "))
    size = int(input(f"Enter payload size in bytes (e.g., 2000): "))

    custom_tcp_ping_fragmented(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count, rps, size)