from scapy.all import *
import time

MTU = 1500
IP_HEADER_SIZE = 20
# TCP_HEADER_SIZE tidak perlu dihitung manual di sini
MAX_FRAGMENT_SIZE = MTU - IP_HEADER_SIZE

def custom_tcp_ping_fragmented(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count, rps=1, size=2000):
    interval = 1.0 / rps
    
    total_bytes_sent = 0
    start_time = time.time()
    
    payload = b'X' * size
    
    # Port sumber awal
    current_src_port = src_port

    for i in range(count):
        # <<< PERUBAHAN KUNCI: Inkrementasi port sumber untuk setiap ping baru
        current_src_port += 1
        
        # Buat paket IP besar dengan payload untuk di-fragmentasi
        ip_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=current_src_port, dport=dst_port, flags='S') / Raw(payload)
        
        # Fragmentasi paket IP
        frags = fragment(ip_pkt, fragsize=MAX_FRAGMENT_SIZE)
        
        # Bungkus setiap fragmen IP dengan header Ethernet untuk pengiriman di Layer 2
        ether_frags = [Ether(src=src_mac, dst=dst_mac) / f for f in frags]
        
        # Hitung total byte yang akan dikirim
        for pkt in ether_frags:
            total_bytes_sent += len(pkt)

        # <<< PERUBAHAN KUNCI: Gunakan srp() untuk mengirim SEMUA fragmen dan menunggu jawaban
        # srp() akan mengembalikan pasangan paket (terkirim, diterima)
        ans, unans = srp(ether_frags, timeout=2, verbose=0)
        
        if not ans:
            print(f"Request timed out for ping {i+1} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            # Dapatkan pasangan request/response pertama yang berhasil
            sent_pkt = ans[0][0]
            rcv_pkt = ans[0][1]
            rtt = (rcv_pkt.time - sent_pkt.sent_time) * 1000  # RTT dalam ms
            print(f"Ping {i+1}: RTT = {rtt:.2f} ms from {rcv_pkt[IP].src} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
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
    src_port = 12345
    dst_port = 80

    count = int(input("Enter number of TCP pings to send: "))
    rps = float(input("Enter requests per second: "))
    size = int(input(f"Enter payload size in bytes (e.g., 2000): "))

    custom_tcp_ping_fragmented(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count, rps, size)