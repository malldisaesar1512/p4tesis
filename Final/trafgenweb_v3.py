import requests
import time
import threading
from datetime import datetime
import argparse

# --- Variabel Global untuk menyimpan hasil dari semua thread ---
# List untuk menyimpan RTT (Round-Trip Time) dari request yang berhasil
hasil_rtt = []
# Menghitung jumlah request yang gagal
jumlah_error = 0
# MENGHITUNG TOTAL BYTES YANG DITERIMA DARI SEMUA REQUEST BERHASIL (PERUBAHAN)
total_bytes_diterima = 0
# Lock untuk sinkronisasi akses ke variabel global di atas
lock = threading.Lock()

def kirim_request(url):
    """
    Fungsi yang dijalankan oleh setiap thread untuk mengirim satu HTTP GET request.
    Fungsi ini mengukur RTT, menangani error, dan mengakumulasi ukuran respons.
    """
    global jumlah_error
    global total_bytes_diterima
    
    try:
        waktu_awal_req = time.perf_counter()
        # Mengirim request dengan timeout 10 detik
        response = requests.get(url, timeout=10)
        waktu_akhir_req = time.perf_counter()

        # Memastikan request berhasil (status code 2xx)
        if response.ok:
            rtt = waktu_akhir_req - waktu_awal_req
            # Mendapatkan ukuran konten respons dalam bytes (PERUBAHAN)
            ukuran_respons = len(response.content)
            
            # Menggunakan lock untuk memodifikasi variabel global secara aman
            with lock:
                hasil_rtt.append(rtt)
                total_bytes_diterima += ukuran_respons # (PERUBAHAN)
        else:
            with lock:
                jumlah_error += 1
                
    except requests.exceptions.RequestException:
        # Menangani error koneksi, timeout, dll.
        with lock:
            jumlah_error += 1

def format_bytes(size):
    """Fungsi helper untuk memformat bytes menjadi KB, MB, GB, dll."""
    if size == 0:
        return "0 B"
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size >= power and n < len(power_labels) -1 :
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

def main():
    """
    Fungsi utama untuk mengatur, menjalankan, dan melaporkan hasil traffic generator.
    """
    parser = argparse.ArgumentParser(description="Traffic Generator untuk Website Lokal")
    parser.add_argument('--url', type=str, default="http://192.168.2.2", help="URL target website.")
    parser.add_argument('--total', type=int, default=100, help="Jumlah total request yang akan dikirim.")
    parser.add_argument('--rps', type=int, default=10, help="Jumlah request per second (RPS) yang diinginkan.")
    
    args = parser.parse_args()

    url = args.url
    total_request = args.total
    rps = args.rps
    
    print(f"🚀 Memulai Traffic Generator...")
    print(f"   - URL Target    : {url}")
    print(f"   - Total Request : {total_request}")
    print(f"   - Request/Detik : {rps}")
    print("-" * 30)

    threads = []
    waktu_mulai_total = time.perf_counter()
    waktu_mulai_formatted = datetime.now()

    for i in range(total_request):
        thread = threading.Thread(target=kirim_request, args=(url,))
        threads.append(thread)
        thread.start()
        time.sleep(1.0 / rps)

    for thread in threads:
        thread.join()

    waktu_selesai_total = time.perf_counter()
    waktu_selesai_formatted = datetime.now()

    # --- Kalkulasi Hasil ---
    total_waktu = waktu_selesai_total - waktu_mulai_total
    request_berhasil = len(hasil_rtt)
    
    if request_berhasil > 0:
        rata_rata_rtt = sum(hasil_rtt) / request_berhasil
    else:
        rata_rata_rtt = 0
        
    # KALKULASI THROUGHPUT DALAM BYTES/SECOND (PERUBAHAN)
    if total_waktu > 0:
        throughput_bps = total_bytes_diterima / total_waktu
    else:
        throughput_bps = 0

    # --- Menampilkan Output ---
    print("\n✅ Proses Selesai!")
    print("=" * 35)
    print("📊 HASIL PENGUJIAN")
    print("=" * 35)
    print(f"Waktu Mulai         : {waktu_mulai_formatted.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Waktu Selesai       : {waktu_selesai_formatted.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total Waktu Eksekusi: {total_waktu:.4f} detik")
    print("-" * 35)
    print(f"Request Berhasil    : {request_berhasil}")
    print(f"Request Gagal       : {jumlah_error}")
    print(f"Total Data Diterima : {format_bytes(total_bytes_diterima)}") # (OUTPUT BARU)
    print(f"Average RTT         : {rata_rata_rtt * 1000:.4f} ms")
    # TAMPILKAN THROUGHPUT DALAM FORMAT BYTES/S (PERUBAHAN)
    print(f"Throughput          : {format_bytes(throughput_bps)}/s")
    print("=" * 35)


if __name__ == "__main__":
    main()