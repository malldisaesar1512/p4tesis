from scapy.all import *
import time
import threading

MTU = 1500
IP_HEADER_SIZE = 20
TCP_HEADER_SIZE = 20
MAX_FRAGMENT_SIZE = MTU - IP_HEADER_SIZE

total_bytes_sent = 0
lock = threading.Lock()
rtt_results = []

def send_one_ping(i, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, size):
    global total_bytes_sent
    payload = b'X' * size
    ip_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S') / Raw(payload)
    frags = fragment(ip_pkt, fragsize=MAX_FRAGMENT_SIZE)

    send_time = time.time()
    # Kirim semua fragmen
    for frag in frags:
        ether_frag = Ether(src=src_mac, dst=dst_mac) / frag
        sendp(ether_frag, verbose=0)
        with lock:
            total_bytes_sent += len(ether_frag)

    # Kirim ulang fragmen pertama untuk cek respons (harus dikirim pakai srp1)
    first_frag_pkt = Ether(src=src_mac, dst=dst_mac) / frags[0]
    first_frag_pkt.sent_time = send_time
    resp = srp1(first_frag_pkt, timeout=2, verbose=0)

    if resp is None:
        print(f"[{i+1}] Timeout at {time.strftime('%H:%M:%S')}")
    else:
        rtt = (resp.time - send_time) * 1000
        with lock:
            rtt_results.append(rtt)
        print(f"[{i+1}] RTT: {rtt:.2f} ms at {time.strftime('%H:%M:%S')}")

def custom_tcp_ping_fragmented_parallel(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count, rps=1, size=2000):
    global total_bytes_sent, rtt_results
    total_bytes_sent = 0
    rtt_results = []
    threads = []

    interval = 1.0 / rps
    start_time = time.time()

    for i in range(count):
        t = threading.Thread(target=send_one_ping, args=(i, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, size))
        t.start()
        threads.append(t)
        time.sleep(interval)

    for t in threads:
        t.join()

    end_time = time.time()
    duration = end_time - start_time
    throughput_bps = (total_bytes_sent * 8) / duration
    throughput_bytes = total_bytes_sent / duration

    avg_rtt = sum(rtt_results) / len(rtt_results) if rtt_results else 0

    print(f"\n--- Ping Result Summary ---")
    print(f"Total packets: {count}")
    print(f"Successful: {len(rtt_results)}")
    print(f"Timeouts: {count - len(rtt_results)}")
    print(f"Average RTT: {avg_rtt:.2f} ms")
    print(f"Total bytes sent: {total_bytes_sent} bytes")
    print(f"Throughput: {throughput_bytes:.2f} Bps ({throughput_bps/1000:.2f} Kbps)")
    print(f"Duration: {duration:.2f} sec")

if __name__ == "__main__":
    src_mac = "50:00:00:00:10:00"
    dst_mac = "50:00:00:00:88:01"
    src_ip = "192.168.1.3"
    dst_ip = "192.168.2.2"
    src_port = 12345
    dst_port = 80

    count = int(input("Enter number of TCP pings to send: "))
    rps = float(input("Enter requests per second: "))
    size = int(input(f"Enter packet size in bytes (can be more than MTU {MTU}): "))

    custom_tcp_ping_fragmented_parallel(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, count, rps, size)
