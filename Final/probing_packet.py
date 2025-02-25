from scapy.all import Ether, IP, UDP, sendp, srp, conf
import time

def send_hello_packet(target_ip, iface):
    # Buat paket hello
    hello_packet = Ether()/IP(dst=target_ip)/UDP(sport=12345, dport=12345)/b'Hello, this is a hello packet!'

    # Kirim paket hello melalui interface yang ditentukan
    sendp(hello_packet, iface=iface, verbose=False)
    print(f"Hello packet sent to {target_ip} through interface {iface}.")

def check_link_status(target_ip, iface):
    # Kirim paket ICMP untuk mengecek status link
    response = srp(Ether()/IP(dst=target_ip)/ICMP(), iface=iface, timeout=1, verbose=False)[0]
    
    # Jika ada balasan, link hidup
    if response:
        return 1  # Link hidup
    else:
        return 0  # Link mati

def main():
    target_ip = "192.168.1.1"  # Ganti dengan IP target yang mau dikirimi hello packet
    iface = "ens3"  # Ganti dengan nama interface yang mau dipake
    timeout = 5  # Timeout dalam detik
    start_time = time.time()

    while True:
        # Kirim hello packet
        send_hello_packet(target_ip, iface)

        # Cek status link
        link_status = check_link_status(target_ip, iface)

        print(f"Link status to {target_ip}: {'Hidup' if link_status == 1 else 'Mati'} ({link_status})")

        # Cek waktu
        elapsed_time = time.time() - start_time
        if elapsed_time > timeout:
            print("Probing selesai setelah 5 detik.")
            break

        time.sleep(1)  # Tunggu 1 detik sebelum mengirim lagi

if __name__ == "__main__":
    main()
