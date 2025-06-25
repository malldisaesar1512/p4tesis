import requests
import time

def measure_rtt_and_throughput(url):
    # Mengukur waktu mulai
    start_time = time.time()
    
    # Melakukan request GET ke URL
    response = requests.get(url)
    
    # Mengukur waktu selesai
    end_time = time.time()
    
    # RTT adalah waktu total permintaan dan balasan
    rtt = end_time - start_time
    
    # Menghitung throughput (bit per detik)
    # Ukuran konten dalam byte dikonversi ke bit
    content_length_bits = len(response.content) * 8
    throughput = content_length_bits / rtt  # bit per detik
    
    print(f"RTT: {rtt:.4f} detik")
    print(f"Throughput: {throughput:.2f} bit/detik")
    print(f"Status code: {response.status_code}")

if __name__ == "__main__":
    url = "http://192.168.2.2"
    measure_rtt_and_throughput(url)
