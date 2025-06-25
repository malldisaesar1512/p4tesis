import requests
import time

def measure_rtt_and_throughput_full_content(url):
    start_time = time.time()
    
    response = requests.get(url, stream=True)
    
    total_bytes = 0
    
    # Membaca seluruh content sampai habis
    for chunk in response.iter_content(chunk_size=4096):
        if chunk:  # pastikan chunk tidak kosong
            total_bytes += len(chunk)
    
    end_time = time.time()
    rtt = end_time - start_time
    
    throughput = (total_bytes * 8) / rtt  # bit per detik
    
    print(f"Status code: {response.status_code}")
    print(f"Total content size (bytes): {total_bytes}")
    print(f"RTT (full content): {rtt:.4f} detik")
    print(f"Throughput: {throughput:.2f} bit/detik")

if __name__ == "__main__":
    url = "http://192.168.2.2"
    measure_rtt_and_throughput_full_content(url)
