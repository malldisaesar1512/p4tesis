#!/usr/bin/env python3
import socket
import time
import argparse
import threading
import queue
import random

rtt_list = []
bytes_sent = 0
lock = threading.Lock()

def send_tcp_packet(target, payload_size, results_queue):
    global bytes_sent
    try:
        payload = b'a' * payload_size
        port = random.randint(1024, 65535)
        start = time.time()
        with socket.create_connection((target, port), timeout=2) as sock:
            sock.sendall(payload)
        end = time.time()
        rtt = (end - start) * 1000  # ms
        with lock:
            rtt_list.append(rtt)
            bytes_sent += payload_size
        results_queue.put((True, rtt))
    except Exception as e:
        results_queue.put((False, str(e)))

def traffic_generator(target, total_requests, rps, payload_size):
    results = queue.Queue()
    interval = 1.0 / rps
    threads = []

    print(f"[+] Sending {total_requests} TCP packets to {target} at {rps} RPS")
    print(f"[+] Using random ports (1024–65535)")

    start_time = time.time()
    for i in range(total_requests):
        t = threading.Thread(target=send_tcp_packet, args=(target, payload_size, results))
        t.start()
        threads.append(t)
        time.sleep(interval)

    for t in threads:
        t.join()
    end_time = time.time()

    duration = end_time - start_time
    avg_rtt = sum(rtt_list) / len(rtt_list) if rtt_list else 0
    throughput_mbps = (bytes_sent * 8) / duration / 1_000_000

    print("\n=== Result ===")
    print(f"Total Sent     : {total_requests} packets")
    print(f"Successful     : {len(rtt_list)}")
    print(f"Failed         : {total_requests - len(rtt_list)}")
    print(f"Avg RTT        : {avg_rtt:.2f} ms")
    print(f"Throughput     : {throughput_mbps:.2f} Mbps")
    print(f"Duration       : {duration:.2f} sec")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', type=str, required=True, help="Target IP address")
    parser.add_argument('--num', type=int, default=100, help="Number of TCP packets to send")
    parser.add_argument('--rps', type=int, default=10, help="Requests per second")
    parser.add_argument('--size', type=int, default=100, help="Payload size in bytes")

    args = parser.parse_args()
    traffic_generator(args.target, args.num, args.rps, args.size)
