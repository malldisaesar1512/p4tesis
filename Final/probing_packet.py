import os
import platform
import subprocess
import time

def ping(host):
    # Tentukan perintah ping sesuai dengan OS
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', host]

    try:
        # Eksekusi perintah ping
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        return True  # Link hidup
    except subprocess.CalledProcessError:
        return False  # Link mati

def main():
    target_ip = "192.168.1.1"  # Ganti dengan IP target yang mau diping
    timeout = 5  # Timeout dalam detik
    start_time = time.time()

    while True:
        if ping(target_ip):
            print(f"Link ke {target_ip} hidup!")
        else:
            print(f"Link ke {target_ip} mati!")

        # Cek waktu
        elapsed_time = time.time() - start_time
        if elapsed_time > timeout:
            print("Probing selesai setelah 5 detik.")
            break

        time.sleep(1)  # Tunggu 1 detik sebelum ping lagi

if __name__ == "__main__":
    main()
