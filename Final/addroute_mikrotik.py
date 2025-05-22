from librouteros import connect
from librouteros.exceptions import TrapError

def add_route_to_mikrotik(ip, username, password, dst, gateway):
    try:
        api = connect(username=username, password=password, host=ip)
        api('/ip/route/add', **{
            'dst-address': dst,
            'gateway': gateway
        })
        print(f'Route {dst} via {gateway} added to Mikrotik {ip}')
    except TrapError as e:
        print(f'Failed to add route {dst} via {gateway} to Mikrotik {ip}: {e}')
    except Exception as e:
        print(f'Unexpected error: {e}')

if __name__ == "__main__":
    ip="10.10.1.1"
    username="admin"
    password="123"
    dst="192.168.1.0/24"
    gateway = "10.10.1.2"
    add_route_to_mikrotik(ip, username, password, dst, gateway)