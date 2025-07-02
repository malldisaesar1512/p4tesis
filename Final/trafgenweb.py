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
        start_time = time.time()
        response = requests.get(url, stream=True, timeout=10)
        content = b""
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                content += chunk
        end_time = time.time()
        elapsed = end_time - start_time
        size = len(content)
        print(f"Fetched: {url} ({size} bytes) in {elapsed:.4f} s")
        return size, elapsed
    except requests.RequestException as ex:
        print(f"Failed to fetch {url}: {ex}")
        return 0, 0

def traffic_generator(url, num_requests=10, max_workers=10):
    total_bytes = 0
    total_time = 0.0
    rtt_list = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for i in range(num_requests):
            print(f"\nRequest {i+1} to {url}")
            # Fetch halaman utama
            future_main = executor.submit(fetch_content, url)
            main_bytes, main_time = future_main.result()
            rtt_list.append(main_time)
            total_bytes += main_bytes
            total_time += main_time

            # Fetch ulang halaman utama untuk mengambil resource links
            try:
                response = requests.get(url, timeout=10)
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    html_text = response.text
                    resource_links = extract_links(html_text, url)
                else:
                    resource_links = set()
            except requests.RequestException:
                resource_links = set()

            # Fetch semua resource secara paralel
            futures = {executor.submit(fetch_content, res_url): res_url for res_url in resource_links}
            for future in as_completed(futures):
                res_bytes, res_time = future.result()
                total_bytes += res_bytes
                total_time += res_time

    avg_rtt = sum(rtt_list) / len(rtt_list) if rtt_list else 0
    throughput = total_bytes / total_time if total_time > 0 else 0

    print("\n=== Summary ===")
    print(f"Average RTT (main pages): {avg_rtt:.4f} seconds")
    print(f"Total Data Received (including resources): {total_bytes} bytes")
    print(f"Throughput (including resources): {throughput:.2f} bytes/second")

if __name__ == "__main__":
    target_url = "http://192.168.2.2"
    jumlah_request = int(input("Masukkan jumlah request: "))
    traffic_generator(target_url, jumlah_request)
