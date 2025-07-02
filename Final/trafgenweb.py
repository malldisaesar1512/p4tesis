import requests
import time
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

def extract_links(html, base_url):
    pattern = r'<img[^>]+src=["\'](.*?)["\']|<script[^>]+src=["\'](.*?)["\']|<link[^>]+href=["\'](.*?)["\']'
    matches = re.findall(pattern, html, re.IGNORECASE)
    links = set()
    for match in matches:
        for link in match:
            if link:
                absolute_link = urljoin(base_url, link)
                links.add(absolute_link)
    return links

def fetch_content(url):
    try:
        start = time.time()
        response = requests.get(url, stream=True, timeout=10)
        content = b""
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                content += chunk
        end = time.time()
        size = len(content)
        elapsed = end - start
        return size, elapsed
    except requests.RequestException:
        return 0, 0

def fetch_and_resources(url):
    main_bytes, main_time = fetch_content(url)
    try:
        response = requests.get(url, timeout=10)
        if 'text/html' in response.headers.get('Content-Type', ''):
            resource_links = extract_links(response.text, url)
        else:
            resource_links = set()
    except requests.RequestException:
        resource_links = set()
    
    total_bytes = main_bytes
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(fetch_content, res_url) for res_url in resource_links]
        for future in as_completed(futures):
            res_bytes, _ = future.result()
            total_bytes += res_bytes

    return main_time, total_bytes

def traffic_generator(url, total_requests=10, target_rps=1):
    rtt_list = []
    total_bytes = 0

    start_time = time.time()
    # We will send requests in batches according to target_rps
    requests_sent = 0

    with ThreadPoolExecutor(max_workers=target_rps*2) as executor:
        while requests_sent < total_requests:
            batch_size = min(target_rps, total_requests - requests_sent)
            batch_start = time.time()

            futures = [executor.submit(fetch_and_resources, url) for _ in range(batch_size)]
            for future in as_completed(futures):
                main_time, bytes_received = future.result()
                rtt_list.append(main_time)
                total_bytes += bytes_received

            requests_sent += batch_size

            batch_end = time.time()
            elapsed = batch_end - batch_start
            # Sleep to keep total batch time ~1 second to match target RPS
            if elapsed < 1.0:
                time.sleep(1.0 - elapsed)

    end_time = time.time()
    total_duration = end_time - start_time

    avg_rtt = sum(rtt_list) / len(rtt_list) if rtt_list else 0
    throughput = total_bytes / total_duration if total_duration > 0 else 0
    actual_rps = len(rtt_list) / total_duration if total_duration > 0 else 0

    print("\n=== Summary ===")
    print(f"Average RTT (main pages): {avg_rtt:.4f} seconds")
    print(f"Total Data Received (including resources): {total_bytes} bytes")
    print(f"Total Time (all requests completed): {total_duration:.4f} seconds")
    print(f"Throughput (total bytes / total time): {throughput:.2f} bytes/second")
    print(f"Target Requests Per Second: {target_rps:.2f} req/s")
    print(f"Actual Requests Per Second: {actual_rps:.2f} req/s")

if __name__ == "__main__":
    target_url = "http://192.168.2.2"
    jumlah_request = int(input("Masukkan jumlah total request: "))
    target_rps = float(input("Masukkan target requests per second: "))
    traffic_generator(target_url, jumlah_request, target_rps)
