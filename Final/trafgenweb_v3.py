import requests
import time
import threading
from datetime import datetime
import argparse
import json
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options

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

def get_full_page_load_metrics(url):
    """
    Menggunakan Selenium untuk satu sesi pemuatan halaman penuh.
    Mengembalikan tuple: (total_bytes, load_time).
    """
    total_bytes = 0
    load_time = 0
    
    # --- Pengaturan Selenium ---
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--log-level=3") # Hanya menampilkan error fatal
    logging_prefs = {'performance': 'ALL'}
    chrome_options.set_capability('goog:loggingPrefs', logging_prefs)

    driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options)

    try:
        start_time = time.perf_counter()
        driver.get(url)
        # Ambil metrik 'navigationStart' dan 'loadEventEnd' dari Timing API browser
        navigation_start = driver.execute_script("return window.performance.timing.navigationStart")
        load_event_end = driver.execute_script("return window.performance.timing.loadEventEnd")
        
        # Hitung waktu muat halaman dari perspektif browser
        # Jika load_event_end belum ada (halaman masih loading), fallback ke perf_counter
        if load_event_end > 0:
            load_time = (load_event_end - navigation_start) / 1000.0 # konversi ke detik
        else:
            # Fallback jika timing API gagal
            end_time = time.perf_counter()
            load_time = end_time - start_time
        
        # Mengambil log performa untuk menghitung total bytes
        logs = driver.get_log('performance')
        for entry in logs:
            log = json.loads(entry['message'])['message']
            if log['method'] == 'Network.dataReceived' and 'params' in log and 'encodedDataLength' in log['params']:
                total_bytes += log['params']['encodedDataLength']
                
    except Exception as e:
        print(f"\nError saat menganalisis {url}: {e}")
        return (None, None)
    finally:
        driver.quit()
        
    return (total_bytes, load_time)


def main():
    parser = argparse.ArgumentParser(description="Analisis Beban Halaman Berurutan menggunakan Selenium.")
    parser.add_argument('--url', type=str, default="http://192.168.2.2", help="URL target website.")
    parser.add_argument('--total', type=int, default=5, help="Jumlah total pengujian yang akan dijalankan.")
    
    args = parser.parse_args()

    print(f"🚀 Memulai Analisis Berurutan...")
    print(f"   - URL Target    : {args.url}")
    print(f"   - Jumlah Uji    : {args.total}")
    print("-" * 40)

    hasil_ukuran = []
    hasil_waktu_muat = []
    
    waktu_mulai_total = time.perf_counter()

    for i in range(args.total):
        print(f"Running test [{i+1}/{args.total}]...")
        size, load_time = get_full_page_load_metrics(args.url)
        if size is not None and load_time is not None:
            hasil_ukuran.append(size)
            hasil_waktu_muat.append(load_time)

    waktu_selesai_total = time.perf_counter()
    
    # --- Kalkulasi Hasil ---
    jumlah_sukses = len(hasil_ukuran)
    if jumlah_sukses > 0:
        rata_rata_ukuran = sum(hasil_ukuran) / jumlah_sukses
        rata_rata_waktu = sum(hasil_waktu_muat) / jumlah_sukses
        # Throughput = rata-rata data yang diunduh per detik selama rata-rata waktu muat
        avg_throughput = rata_rata_ukuran / rata_rata_waktu if rata_rata_waktu > 0 else 0
    else:
        rata_rata_ukuran = 0
        rata_rata_waktu = 0
        avg_throughput = 0

    # --- Menampilkan Output ---
    print("\n✅ Proses Selesai!")
    print("=" * 40)
    print("📊 HASIL PENGUJIAN HALAMAN LENGKAP")
    print("=" * 40)
    print(f"Total Waktu Eksekusi  : {waktu_selesai_total - waktu_mulai_total:.2f} detik")
    print(f"Pengujian Berhasil    : {jumlah_sukses}/{args.total}")
    print("-" * 40)
    print(f"Rata-rata Waktu Muat  : {rata_rata_waktu:.2f} detik/halaman")
    print(f"Rata-rata Ukuran      : {format_bytes(rata_rata_ukuran)}/halaman")
    print(f"Rata-rata Throughput  : {format_bytes(avg_throughput)}/s")
    print("=" * 40)


if __name__ == "__main__":
    main()