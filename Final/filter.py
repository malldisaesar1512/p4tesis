import csv
from scapy.all import sniff, TCP, ICMP
from datetime import datetime
import threading
import time

# --- Konfigurasi ---
OUTPUT_CSV_FILE = 'network_log.csv'
INTERFACES = ['ens5', 'ens6', 'ens7']  # Ganti dengan nama interface Anda

# Kunci (lock) untuk memastikan hanya satu thread yang bisa menulis ke file pada satu waktu
file_lock = threading.Lock()

def monitor_packet(packet, interface_name, csv_writer):
    """
    Fungsi ini dipanggil untuk setiap paket yang ditangkap.
    Jika paket cocok dengan kriteria, ia akan menulis baris ke file CSV.
    """
    waktu = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    log_data = None

    # Filter untuk paket TCP SYN
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        # [Waktu, Interface Keluar, Detail Paket]
        log_data = [waktu, interface_name, f"TCP SYN: {packet.summary()}"]
    
    # Filter untuk paket ICMP Echo Request (ping)
    elif packet.haslayer(ICMP) and packet[ICMP].type == 8:
        log_data = [waktu, interface_name, f"ICMP Echo Request: {packet.summary()}"]

    if log_data:
        # Menggunakan 'with' pada lock untuk akuisisi dan rilis otomatis
        with file_lock:
            # Menulis baris data ke file CSV
            csv_writer.writerow(log_data)
            # Memberi feedback langsung di konsol (opsional)
            print(f"Logged: {','.join(log_data)}")

def start_sniff(interface_name, csv_writer):
    """Memulai proses sniffing pada interface yang ditentukan."""
    print(f"Memulai monitoring pada interface {interface_name}...")
    try:
        # `prn` akan memanggil fungsi monitor_packet untuk setiap paket
        # `store=0` agar paket tidak disimpan di memori
        sniff(iface=interface_name, prn=lambda pkt: monitor_packet(pkt, interface_name, csv_writer), store=0)
    except Exception as e:
        print(f"Error pada interface {interface_name}: {e}")

# --- Eksekusi Utama ---
if __name__ == "__main__":
    try:
        # Membuka file CSV dalam mode tulis ('w')
        # newline='' mencegah baris kosong tambahan di file CSV
        with open(OUTPUT_CSV_FILE, 'w', newline='', encoding='utf-8') as csvfile:
            # Membuat objek writer CSV
            writer = csv.writer(csvfile, delimiter=',')
            
            # Menulis baris header
            # Kolom "InterfaceKeluar" adalah interface tempat paket ditangkap
            writer.writerow(['Waktu', 'InterfaceKeluar', 'DetailPaket'])
            
            print(f"Output akan disimpan di: {OUTPUT_CSV_FILE}")
            print("Tekan Ctrl+C untuk menghentikan monitoring.")

            threads = []
            for iface in INTERFACES:
                # Membuat thread untuk setiap interface
                # 'args' berisi argumen yang akan diberikan ke fungsi 'start_sniff'
                t = threading.Thread(target=start_sniff, args=(iface, writer))
                t.daemon = True  # Thread akan berhenti jika program utama berhenti
                t.start()
                threads.append(t)

            # Menjaga program utama tetap berjalan selagi thread bekerja
            while True:
                time.sleep(1)

    except KeyboardInterrupt:
        print(f"\nMonitoring dihentikan. File '{OUTPUT_CSV_FILE}' telah disimpan.")
    except Exception as e:
        print(f"Terjadi error: {e}")