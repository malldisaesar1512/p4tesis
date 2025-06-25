import requests
import time

def measure_rtt_and_throughput_full_content(url):
    start_time = time.time()
    
    # Request dengan streaming
    response = requests.get(url, stream=True)
    
    total_bytes = 0
    
    # Membaca content secara bertahap sampai habis
    for chunk in response.iter_content(chunk_size=4096):
        if chunk:
            total_bytes += len(chunk)
    
    end_time = time.time()
    rtt = end_time - start_time
    
    # Throughput dalam bit per detik
    throughput = (total_bytes * 8) / rtt
    
    print(f"Status code: {response.status_code}")
    print(f"Total content size: {total_bytes} bytes")
    print(f"RTT (full content): {rtt:.4f} detik")
    print(f"Throughput: {throughput:.2f} bit/detik")

if __name__ == "__main__":
    url = "http://192.168.2.2"
    measure_rtt_and_throughput_full_content(url)
