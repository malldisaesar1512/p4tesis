import requests
import time

def traffic_generator(url, num_requests=10):
    rtt_list = []
    total_bytes = 0
    total_time = 0.0

    for i in range(num_requests):
        start_time = time.time()
        response = requests.get(url, stream=True)
        
        # Membaca keseluruhan content secara eksplisit agar pastikan content sepenuhnya diterima
        content = b""
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                content += chunk
        end_time = time.time()

        rtt = end_time - start_time
        rtt_list.append(rtt)

        data_length = len(content)
        total_bytes += data_length
        total_time += rtt

        print(f"Request {i+1}: RTT = {rtt:.4f} s, Data received = {data_length} bytes")

    avg_rtt = sum(rtt_list) / len(rtt_list)
    throughput = total_bytes / total_time if total_time > 0 else 0

    print("\n=== Summary ===")
    print(f"Average RTT: {avg_rtt:.4f} seconds")
    print(f"Total Data Received: {total_bytes} bytes")
    print(f"Throughput: {throughput:.2f} bytes/second")

if __name__ == "__main__":
    target_url = "http://192.168.2.2"
    jumlah_request = int(input("Masukkan jumlah request: "))
    traffic_generator(target_url, jumlah_request)
