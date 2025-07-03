import time
import argparse
import concurrent.futures
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def format_bytes(size):
    """Fungsi helper untuk memformat bytes menjadi KB, MB, GB, dll."""
    if size is None or size == 0:
        return "0 B"
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size >= power and n < len(power_labels) - 1:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}"

def fetch_page_and_assets(url, test_num, total_tests):
    """
    Mengunduh halaman utama dan semua aset yang tertaut di HTML-nya.
    Mengembalikan tuple (total_bytes, duration).
    """
    print(f"  -> Memulai tes [{test_num}/{total_tests}] untuk {url}...")
    start_time = time.perf_counter()
    total_bytes = 0
    
    try:
        # 1. Ambil halaman HTML utama
        response = requests.get(url, timeout=10)
        response.raise_for_status() # Lontarkan error jika status bukan 2xx
        total_bytes += len(response.content)
        
        # 2. Parse HTML untuk mencari aset
        soup = BeautifulSoup(response.text, 'html.parser')
        asset_urls = set()

        # Cari tag link (CSS), script (JS), dan img (gambar)
        for tag in soup.find_all(['link', 'script', 'img']):
            if tag.name == 'link' and tag.has_attr('href'):
                asset_urls.add(urljoin(url, tag['href']))
            elif tag.name == 'script' and tag.has_attr('src'):
                asset_urls.add(urljoin(url, tag['src']))
            elif tag.name == 'img' and tag.has_attr('src'):
                asset_urls.add(urljoin(url, tag['src']))
        
        # 3. Ambil setiap aset
        # (Dalam contoh ini kita lakukan sekuensial untuk kesederhanaan,
        # namun ini sudah jauh lebih cepat dari Selenium)
        for asset_url in asset_urls:
            try:
                asset_response = requests.get(asset_url, timeout=5)
                if asset_response.ok:
                    total_bytes += len(asset_response.content)
            except requests.exceptions.RequestException:
                # Abaikan aset yang gagal diunduh
                pass
                
    except requests.exceptions.RequestException as e:
        print(f"\nError saat mengambil halaman utama [{test_num}]: {e}")
        return (None, None)

    duration = time.perf_counter() - start_time
    print(f"  <- Selesai tes [{test_num}/{total_tests}] dalam {duration:.2f} detik. Total ukuran: {format_bytes(total_bytes)}")
    return (total_bytes, duration)

def main():
    parser = argparse.ArgumentParser(description="Traffic Generator dengan Parsing Aset (Non-Selenium).")
    parser.add_argument('--url', type=str, default="http://192.168.2.2", help="URL target website.")
    parser.add_argument('--total', type=int, default=50, help="Jumlah total pengujian yang akan dijalankan.")
    parser.add_argument('--rps', type=int, default=10, help="Jumlah tes paralel (concurrent requests).")
    
    args = parser.parse_args()

    print(f"🚀 Memulai Analisis Paralel (Metode Parsing)...")
    print(f"   - URL Target            : {args.url}")
    print(f"   - Jumlah Total Uji      : {args.total}")
    print(f"   - Tes Paralel (RPS)     : {args.rps}")
    print("-" * 40)

    results = []
    
    waktu_mulai_total = time.perf_counter()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.rps) as executor:
        futures = [executor.submit(fetch_page_and_assets, args.url, i+1, args.total) for i in range(args.total)]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result[0] is not None:
                results.append(result)

    waktu_selesai_total = time.perf_counter()
    
    jumlah_sukses = len(results)
    if jumlah_sukses > 0:
        total_ukuran = sum(r[0] for r in results)
        total_waktu_muat = sum(r[1] for r in results)
        rata_rata_ukuran = total_ukuran / jumlah_sukses
        rata_rata_waktu = total_waktu_muat / jumlah_sukses
        # Throughput keseluruhan sistem (total data / total waktu eksekusi)
        overall_throughput = total_ukuran / (waktu_selesai_total - waktu_mulai_total)
    else:
        rata_rata_ukuran = 0
        rata_rata_waktu = 0
        overall_throughput = 0

    print("\n✅ Proses Selesai!")
    print("=" * 40)
    print("📊 HASIL PENGUJIAN (METODE PARSING)")
    print("=" * 40)
    print(f"Total Waktu Eksekusi  : {waktu_selesai_total - waktu_mulai_total:.2f} detik")
    print(f"Pengujian Berhasil    : {jumlah_sukses}/{args.total}")
    print("-" * 40)
    print(f"Rata-rata Waktu Muat  : {rata_rata_waktu:.2f} detik/halaman")
    print(f"Rata-rata Ukuran      : {format_bytes(rata_rata_ukuran)}/halaman")
    print(f"Throughput Sistem     : {format_bytes(overall_throughput)}/s")
    print("=" * 40)

if __name__ == "__main__":
    main()