from routeros_api import RouterOsApiPool

# Koneksi ke RouterOS
api_pool = RouterOsApiPool('10.10.1.1', username='admin', password='123')
api = api_pool.get_api()

# Mengambil resource routing
route_resource = api.get_resource('/ip/route')

# Mendapatkan semua routing yang ada
routes = route_resource.get()

# Print semua routing
for route in routes:
    print(f"Destination: {route.get('dst-address')}, Gateway: {route.get('gateway')}, Distance: {route.get('distance')}")

# Tutup koneksi
api_pool.disconnect()
