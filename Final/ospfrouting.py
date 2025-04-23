from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.contrib import ospf


# Konstanta tipe paket OSPF
OSPF_HELLO = 1
OSPF_DBD = 2
OSPF_LSR = 3
OSPF_LSU = 4
OSPF_LSACK = 5

# Variabel penyimpanan data hasil tangkapan paket OSPF berdasarkan jenisnya:
hello_packets_received = []
dbd_packets_received = []
lsr_packets_received = []
lsu_routes_received = []

def parse_ospf_packet(pkt):
    ospf_layer = pkt.getlayer(ospf.OSPF)   # <-- pakai ospf.OSPF
    
    if not ospf_layer:
        return None
    
    pkt_type = ospf_layer.type
    
    if pkt_type == OSPF_HELLO:
        hello_info={
            "router_id": ospf_layer.routerid,
            "area_id": ospf_layer.area,
            "hello_interval": getattr(ospf_layer, 'hellointerval', None),
            "neighbors": getattr(ospf_layer, 'neighbors', [])
        }
        print(f"[INFO] Menerima Paket HELLO: {hello_info}")
        hello_packets_received.append(hello_info)
        
    elif pkt_type == OSPF_DBD:
        dbd_info={
            "seq_num": getattr(ospf_layer, 'seqnum', None),
            "flags": getattr(ospf_layer, 'flags', None),
        }
        print(f"[INFO] Menerima Paket DBD: {dbd_info}")
        dbd_packets_received.append(dbd_info)
        
    elif pkt_type == OSPF_LSR:
       lsr_payload=bytes(ospf_layer.payload)
       print(f"[INFO] Menerima Paket LSR dengan panjang payload: {len(lsr_payload)} bytes")
       lsr_packets_received.append(lsr_payload)

       
    elif pkt_type == OSPF_LSU:
         lsu_data=bytes(ospf_layer.payload)         
         print(f"[INFO] Menerima Paket LSU dengan panjang payload: {len(lsu_data)} bytes")
         lsu_routes_received.append(lsu_data)

def send_hello_packet(dst_ip="224.0.0.5", iface="ens5"):
     src_ip=get_if_addr(iface)
   
     ether=Ether(dst="01:00:5e:00:00:05")   
     
     ip_pkt=IP(src=src_ip,dst=dst_ip,proto=89)  
      
     hello_pkt=(ether/ip_pkt/
                ospf.OSPF(
                    type=1,
                    routerid=src_ip,
                    area='0.0.0.0',
                    hellointerval=10,
                    options="\x02",
                )
               )
     
     sendp(hello_pkt,iface=iface)
     
def main():
   iface="ens5"
   print("Mulai menangkap trafik Mikrotik's OSPF...")
   
   def process_packet(pkt):
      if IP in pkt and pkt[IP].proto==89 and pkt.haslayer(ospo.OSPF):
          parse_ospf_packet(pkt)

          if pkt[ospo.OSPF].type==1:
              send_hello_packet(iface=iface)

   sniff(filter="ip proto 89", prn=process_packet, iface=iface)


if __name__=="__main__":
   main()