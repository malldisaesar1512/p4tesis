import argparse
import requests
import time
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

# Header untuk meniru browser, mengurangi kemungkinan diblokir
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

def format_bytes(size):
    """Fungsi helper untuk memformat bytes menjadi KB, MB, GB."""
    if size is None or size == 0:
        return "0 B"
    power = 1024
    n = 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB'}
    while size >= power and n < len(power_labels) - 1:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}"

def extract_links_bs(html_content, base_url):
    """Mengekstrak link aset menggunakan BeautifulSoup agar lebih robust."""
    soup = BeautifulSoup(html_content, 'html.parser')
    links = set()
    for tag in soup.find_all(['link', 'script', 'img']):
        if tag.name == 'link' and tag.has_attr('href'):
            links.add(urljoin(base_url, tag['href']))
        elif tag.name == 'script' and tag.has_attr('src'):
            links.add(urljoin(base_url, tag['src']))
        elif tag.name == 'img' and tag.has_attr('src'):
            links.add(urljoin(base_url, tag['src']))
    return links

def fetch_content(url):
    """Mengunduh konten dari satu URL (biasanya aset)."""
    try:
        response = requests.get(url, headers=REQUEST_HEADERS, timeout=3000)
        response.raise_for_status()
        return len(response.content)
    except requests.RequestException:
        return 0

def fetch_full_request(url):
    """Satu siklus lengkap: mengunduh halaman utama, mem-parsing, dan mengunduh semua asetnya."""
    start_time = time.perf_counter()
    try:
        main_response = requests.get(url, headers=REQUEST_HEADERS, timeout=3000)
        main_response.raise_for_status()
        main_content_bytes = main_response.content
        main_content_length = len(main_content_bytes)

        content_type = main_response.headers.get('Content-Type', '')
        if 'text/html' in content_type:
            html_str = main_content_bytes.decode(main_response.encoding or 'utf-8', errors='replace')
            resource_links = extract_links_bs(html_str, url)
        else:
            resource_links = set()

    except requests.RequestException:
        return 0, 0.0, False

    resource_total_size = 0
    if resource_links:
        max_asset_workers = min(10, len(resource_links))
        with ThreadPoolExecutor(max_workers=max_asset_workers) as executor:
            futures = [executor.submit(fetch_content, res_url) for res_url in resource_links]
            for future in as_completed(futures):
                resource_total_size += future.result()

    end_time = time.perf_counter()
    total_bytes = main_content_length + resource_total_size
    total_time = end_time - start_time
    return total_bytes, total_time, True

def traffic_generator(url, total_requests, rps):
    """Orkestrasi utama dengan rate limiting yang presisi."""
    rtt_list = []
    total_bytes_transferred = 0
    successful_requests = 0

    print(f"Memulai traffic generator untuk {total_requests} request ke {url}...")
    print(f"RPS yang diatur: {rps} req/detik\n")

    # Ukuran worker pool disarankan sedikit lebih besar dari RPS untuk menangani antrian
    max_workers = rps * 2 

    start_time_overall = time.perf_counter()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        dispatch_start_time = time.perf_counter()
        
        # --- BLOK RATE LIMITER ---
        # Loop ini bertanggung jawab untuk mengirimkan tugas pada kecepatan yang tepat.
        for i in range(total_requests):
            # Hitung waktu seharusnya tugas ini dikirim
            expected_dispatch_time = dispatch_start_time + (i / rps)
            
            # Tidur hingga waktu pengiriman yang tepat tiba
            sleep_duration = expected_dispatch_time - time.perf_counter()
            if sleep_duration > 0:
                time.sleep(sleep_duration)
            
            # Kirim tugas ke thread pool untuk dieksekusi di latar belakang
            futures.append(executor.submit(fetch_full_request, url))
        # --- AKHIR BLOK RATE LIMITER ---

        # Mengumpulkan hasil dari tugas yang telah selesai
        for future in as_completed(futures):
            try:
                bytes_recv, rtt, success = future.result()
                if success:
                    total_bytes_transferred += bytes_recv
                    rtt_list.append(rtt)
                    successful_requests += 1
            except Exception as e:
                print(f"Eksekusi sebuah request gagal: {e}")

    end_time_overall = time.perf_counter()
    total_time_wallclock = end_time_overall - start_time_overall

    avg_rtt = sum(rtt_list) / len(rtt_list) if rtt_list else 0
    throughput_bps = total_bytes_transferred / total_time_wallclock if total_time_wallclock > 0 else 0
    actual_rps = successful_requests / total_time_wallclock if total_time_wallclock > 0 else 0

    print("\n" + "="*20 + " RINGKASAN " + "="*20)
    print(f"Waktu Total Eksekusi      : {total_time_wallclock:.2f} detik")
    print(f"Total Request Berhasil    : {successful_requests}/{total_requests}")
    print(f"Total Data Diterima       : {format_bytes(total_bytes_transferred)}")
    print("-" * 51)
    print(f"Rata-rata RTT (Halaman)   : {avg_rtt:.4f} detik")
    print(f"RPS Diatur                : {rps} req/detik")
    print(f"RPS Aktual (Tercapai)     : {actual_rps:.2f} req/detik")
    print(f"Throughput Sistem         : {format_bytes(throughput_bps)}/detik")
    print("=" * 51)

def main():
    parser = argparse.ArgumentParser(description="Traffic Generator dengan Rate Limiting Presisi")
    parser.add_argument('--url', type=str, required=True, help='URL target yang akan diuji.')
    parser.add_argument('--jumlah', type=int, required=True, help='Jumlah total request yang akan dikirim.')
    parser.add_argument('--rps', type=int, required=True, help='Request Per Second yang diinginkan.')
    args = parser.parse_args()

    if args.rps <= 0:
        print("RPS harus lebih besar dari 0.")
        return

    traffic_generator(args.url, args.jumlah, args.rps)

if __name__ == "__main__":
    main()