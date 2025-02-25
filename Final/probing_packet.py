import os
import platform
import subprocess
import time
from scapy.all import sr1, IP, ICMP

def ping(host, iface):
    # Buat paket ICMP
    packet = IP(dst=host)/ICMP()

    try:
        # Kirim paket dan tunggu balasan
        response = sr1(packet, iface=iface, timeout=1, verbose=False)
        if response:
            return True  # Link hidup
        else:
            return False  # Link mati
    except Exception as e:
        print(f"Error: {e}")
        return False  # Link mati

def main():
    target_ip = "192.168.1.1"  # Ganti dengan IP target yang mau diping
    iface = "eth0"  # Ganti dengan nama interface yang mau dipake
    timeout = 5  # Timeout dalam detik
    start_time = time.time()

    while True:
        if ping(target_ip, iface):
            print(f"Link ke {target_ip} hidup melalui interface {iface}!")
        else:
            print(f"Link ke {target_ip} mati melalui interface {iface}!")

        # Cek waktu
        elapsed_time = time.time() - start_time
        if elapsed_time > timeout:
            print("Probing selesai setelah 5 detik.")
            break

        time.sleep(1)  # Tunggu 1 detik sebelum ping lagi

if __name__ == "__main__":
    main()
