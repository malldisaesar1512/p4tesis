from scapy.all import Ether, IP, UDP, sendp
import time

def send_hello_packet(target_ip, iface):
    # Buat paket hello
    hello_packet = Ether()/IP(dst=target_ip)/UDP(sport=12345, dport=12345)/b'Hello, this is a hello packet!'

    # Kirim paket hello melalui interface yang ditentukan
    sendp(hello_packet, iface=iface, verbose=False)
    print(f"Hello packet sent to {target_ip} through interface {iface}.")

def main():
    target_ip = "192.168.1.1"  # Ganti dengan IP target yang mau dikirimi hello packet
    iface = "ens3"  # Ganti dengan nama interface yang mau dipake
    timeout = 5  # Timeout dalam detik
    start_time = time.time()

    while True:
        # Kirim hello packet
        send_hello_packet(target_ip, iface)

        # Cek status pengiriman
        # Di sini kita anggap pengiriman berhasil, karena sendp tidak mengembalikan status
        # Namun, kita bisa menandai status link berdasarkan asumsi
        link_status = 1  # 1 berarti link hidup

        # Simulasi pengecekan status (misalnya, kita bisa menggunakan ping atau metode lain)
        # Jika ada metode untuk mengecek, bisa ditambahkan di sini
        # Misalnya, jika tidak ada balasan dalam waktu tertentu, kita set link_status ke 0
        # Untuk contoh ini, kita anggap selalu berhasil
        # Jika ingin simulasi, bisa tambahkan logika untuk mengubah link_status

        print(f"Link status to {target_ip}: {'Hidup' if link_status == 1 else 'Mati'} ({link_status})")

        # Cek waktu
        elapsed_time = time.time() - start_time
        if elapsed_time > timeout:
            print("Probing selesai setelah 5 detik.")
            break

        time.sleep(1)  # Tunggu 1 detik sebelum mengirim lagi

if __name__ == "__main__":
    main()
