import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def measure_total_page_content(url):
    start_time = time.time()
    session = requests.Session()
    total_bytes = 0
    
    # Request HTML utama
    try:
        response = session.get(url, stream=True)
        response.raise_for_status()
    except Exception as e:
        print(f"Gagal request halaman: {e}")
        return
    
    # Hitung size HTML
    html_bytes = 0
    for chunk in response.iter_content(chunk_size=4096):
        if chunk:
            html_bytes += len(chunk)
    total_bytes += html_bytes
    
    # Parse HTML untuk dapatkan semua resource penting
    response_content = response.content
    soup = BeautifulSoup(response_content, 'html.parser')
    
    # Kumpulkan URL resource dari img, link(css), script(js)
    resource_urls = set()
    # img src
    for img in soup.find_all('img'):
        src = img.get('src')
        if src:
            resource_urls.add(urljoin(url, src))
    # link rel=stylesheet
    for link_tag in soup.find_all('link', rel='stylesheet'):
        href = link_tag.get('href')
        if href:
            resource_urls.add(urljoin(url, href))
    # script src
    for script in soup.find_all('script', src=True):
        src = script.get('src')
        if src:
            resource_urls.add(urljoin(url, src))
    
    # Download semua resource dan hitung size
    for resource_url in resource_urls:
        try:
            resource_response = session.get(resource_url, stream=True, timeout=10)
            resource_response.raise_for_status()
            resource_bytes = 0
            for chunk in resource_response.iter_content(chunk_size=4096):
                if chunk:
                    resource_bytes += len(chunk)
            total_bytes += resource_bytes
        except Exception as e:
            print(f"Gagal request resource {resource_url}: {e}")
    
    end_time = time.time()
    rtt_total = end_time - start_time
    throughput = (total_bytes * 8) / rtt_total if rtt_total > 0 else 0
    
    print(f"Total konten (HTML + img + CSS + JS): {total_bytes} bytes")
    print(f"Waktu total (RTT-like): {rtt_total:.4f} detik")
    print(f"Throughput: {throughput:.2f} bit/detik")

if __name__ == "__main__":
    url = "http://192.168.2.2"
    measure_total_page_content(url)
