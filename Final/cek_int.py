from scapy.all import get_if_list, get_if_addr

# Dapatkan daftar semua interface
interfaces = get_if_list()

print("Daftar interface dan IP-nya:")

for iface in interfaces:
    try:
        ip = get_if_addr(iface)
        # Abaikan interface tanpa IP atau loopback
        if ip and ip != "0.0.0.0" and not ip.startswith("127."):
            print(f"Interface: {iface}, IP Address: {ip}")
    except Exception as e:
        # Beberapa interface mungkin tidak punya IP, abaikan error
        pass
