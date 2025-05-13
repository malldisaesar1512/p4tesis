import psutil
import socket
import ipaddress

def get_active_interfaces_info():
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface, addr_list in addrs.items():
        if iface in stats and stats[iface].isup:
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    netmask = addr.netmask
                    if ip and netmask and ip != "127.0.0.1":
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        print(f"Interface: {iface}")
                        print(f"  IP Address: {ip}")
                        print(f"  Netmask: {netmask}")
                        print(f"  Network: {network.network_address}/{network.prefixlen}")

if __name__ == "__main__":
    get_active_interfaces_info()
