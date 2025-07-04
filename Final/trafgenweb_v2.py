import argparse
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
        response = requests.get(url, stream=True, timeout=100)
        content = b""
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                content += chunk
        return len(content)
    except requests.RequestException as e:
        print(f"Failed to fetch resource {url}: {e}")
        return 0

def fetch_full_request(url):
    start_time = time.time()
    try:
        response = requests.get(url, timeout=100, stream=True)
        content_bytes = b""
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                content_bytes += chunk
        main_content_length = len(content_bytes)
        content_type = response.headers.get('Content-Type', '')

        if 'text/html' in content_type:
            content_str = content_bytes.decode(response.encoding or 'utf-8', errors='replace')
            resource_links = extract_links(content_str, url)
        else:
            resource_links = set()
    except requests.RequestException as e:
        print(f"Failed to fetch main URL {url}: {e}")
        return 0, 0.0

    resource_total_size = 0
    max_resource_workers = min(10, len(resource_links)) if resource_links else 1
    with ThreadPoolExecutor(max_workers=max_resource_workers) as executor:
        futures = [executor.submit(fetch_content, res_url) for res_url in resource_links]
        for future in as_completed(futures):
            resource_total_size += future.result()

    end_time = time.time()
    total_bytes = main_content_length + resource_total_size
    total_time = end_time - start_time
    return total_bytes, total_time

def traffic_generator(url, total_requests, target_rps):
    rtt_list = []
    total_bytes = 0

    print(f"Starting traffic generator for {total_requests} requests with target {target_rps} requests/sec...\n")

    start_time_overall = time.time()  # mulai waktu keseluruhan

    max_workers = max(10, target_rps * 2)
    max_workers = min(max_workers, 100)  # batas maksimal worker menjadi 100

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for _ in range(total_requests):
            futures.append(executor.submit(fetch_full_request, url))

        for future in as_completed(futures):
            try:
                bytes_recv, rtt = future.result()
                total_bytes += bytes_recv
                if rtt > 0:
                    rtt_list.append(rtt)
            except Exception as e:
                print(f"Request execution failed: {e}")

    end_time_overall = time.time()  # selesai waktu keseluruhan

    total_time_wallclock = end_time_overall - start_time_overall

    avg_rtt = sum(rtt_list) / len(rtt_list) if rtt_list else 0
    throughput = total_bytes / total_time_wallclock if total_time_wallclock > 0 else 0
    actual_rps = len(rtt_list) / total_time_wallclock if total_time_wallclock > 0 else 0

    print("\n=== Summary ===")
    print(f"Average RTT (full page + all resources): {avg_rtt:.4f} seconds")
    print(f"Total Data Received (including resources): {total_bytes} bytes")
    print(f"Total Time (wall clock): {total_time_wallclock:.4f} seconds")
    print(f"Throughput (total bytes / total time): {throughput:.2f} bytes/second")
    print(f"Target Requests Per Second: {target_rps} req/s")
    print(f"Actual Requests Per Second (approx): {actual_rps:.2f} req/s")

def main():
    parser = argparse.ArgumentParser(description="Improved Traffic Generator with full resource fetch")
    parser.add_argument('--url', type=str, required=True, help='Target URL to request')
    parser.add_argument('--req', type=int, required=True, help='Jumlah total request')
    parser.add_argument('--rps', type=int, required=True, help='Target requests per second')
    args = parser.parse_args()

    traffic_generator(args.url, args.req, args.rps)

if __name__ == "__main__":
    main()
