#!/usr/bin/env python3
import time
from collections import defaultdict
from scapy.all import *
from scapy.contrib.ospf import *

# Konfigurasi OSPF Router
ROUTER_ID = "192.168.100.1"      # Router ID unik node ini (ubah sesuai kebutuhan)
AREA_ID = "0.0.0.0"              # Area OSPF (biasanya backbone area 0)
HELLO_INTERVAL = 10              # Interval hello dalam detik
NETWORK_MASK = "255.255.255.0"   # Subnet mask jaringan lokal

# Database Link-State dan Neighbor Tracking
LINK_STATE_DB = dict()           # key: (lsa_type, link_id, adv_router), value: LSA object + metadata 
NEIGHBORS_DB = set()

def create_ospf_hello_packet(dst_ip):
    """Membuat paket Hello OSPF"""
    pkt = IP(dst=dst_ip)/OSPF_Hdr(
        src=ROUTER_ID,
        area=AREA_ID,
        type=1  # Hello Packet type
    )/OSPF_Hello(
        mask=NETWORK_MASK,
        hellointerval=HELLO_INTERVAL,
        options=[E_Router_LSA()]  # opsi router LSA dasar; bisa disesuaikan jika perlu 
    )
    return pkt

def create_ospf_lsu_packet(dst_ip, lsa_list):
    """Membuat paket Link State Update (LSU) berisi list LSA"""
    pkt = IP(dst=dst_ip)/OSPF_Hdr(
        src=ROUTER_ID,
        area=AREA_ID,
        type=4  # LSU Packet type  
    )/OSPF_LSUpd(
        lsalist=[lsa.copy() for lsa in lsa_list]
    )
    return pkt

def process_link_state_request(lsr_packet):
    """Memproses Link State Request dan membalas dengan LSU yang diminta"""
    
    if not hasattr(lsr_packet[OSPF_LSReq], 'requests'):
        print("[!] Format LSR tidak valid")
        return
    
    requested_lsas = []
    
    for req in lsr_packet[OSPF_LSReq].requests:
        
        try:
            lsa_type = req.type  
            link_id = req.id  
            adv_router = req.advertisingrouter
            
            key = (lsa_type, link_id, adv_router)
            
            if key in LINK_STATE_DB:
                requested_lsas.append(LINK_STATE_DB[key]['data'])
                print(f"[+] Menambahkan LSA tipe {lsa_type} untuk {link_id} dari {adv_router}")
                
            else:
                print(f"[!] Tidak menemukan LSA tipe {lsa_type} untuk {link_id} dari {adv_router}")
                
        except Exception as e:
            print(f"[!] Error memproses request: {str(e)}")
    
    if requested_lsas:
        reply_pkt = create_ospf_lsu_packet(lsr_packet[IP].src, requested_lsas)
        
        send(reply_pkt, verbose=False)
        
        print(f"[LSU] Mengirim {len(requested_lsas)} LSA ke {lsr_packet[IP].src}")

def update_link_state_database(lsu_packet): 
     """Memperbarui database berdasarkan LSU yang diterima"""   
     
     if not hasattr(lsu_packet[OSPF_LSUpd], 'lsalist'):
          return False

     for lsa in lsu_packet[OSPF_LSUpd].lsalist:
         try:   
             lsa_type=getattr(lsa,'type',None)
             link_id=getattr(lsa,'id',None)
             adv_router=getattr(lsa,'advrouter',None)

             key=(lsa_type ,link_id ,adv_router)

             current_entry = LINK_STATE_DB.get(key,None)

             new_seq=getattr(lsa ,'seq',-1)             
             current_seq=-1 if current_entry is None else getattr(current_entry['data'],'seq',-1)

             if new_seq > current_seq or current_entry is None :
                 LINK_STATE_DB[key]={'data':lsa,'timestamp':time.time()}
                 print(f"[DB] Memperbarui LSA tipe:{lsa_type}, ID:{link_id}, AdvRouter:{adv_router}, Seq:{new_seq}")

         except Exception as e :   
               print(f"[!] Error proses LSU :{str(e)}") 

def process_hello(packet):
      router_srcid=str(packet[OSPF_Hdr].src)
      NEIGHBORS_DB.add(router_srcid)  # Simpan neighbor
      
      replypkt=create_ospf_hello_packet(packet[IP].src)      
      send(replypkt,verbose=False )
      
      print(f"[Hello] Balasan dikirim ke router ID: {router_srcid}")

def process_db_description(packet):
     print("[DBD] Menerima Database Description - fitur belum diimplementasikan")

def process_ospf_packet(packet):  
     try:   
          if not packet.haslayer(IP) or not packet.haslayer(OSPF_Hdr): 
              return False  

          ospfhdr=packet[OSPF_Hdr]
          srcip=str(packet[IP].src)
          areaid=str(ospfhdr.area)

          print("\n=======================================")
          print(f"Paket OSPF diterima dari IP={srcip}, Area={areaid}")

          if areaid != AREA_ID :
               print("[Warning] Paket berasal dari Area berbeda - diabaikan")
               return False   

          ptype=int(ospfhdr.type)

          if ptype == 1:#Hello Packet     
               process_hello(packet)    

          elif ptype ==2:#Database Description     
               process_db_description(packet)    

          elif ptype ==3:#Link State Request     
               process_link_state_request(packet)    

          elif ptype ==4:#Link State Update     
               update_link_state_database(packet)    

     except Exception as e :      
           print(f"[Error] Proses paket gagal: {str(e)}")

def start_sniffing():        
       interface=input("Masukkan nama interface jaringan Anda (contoh eth0): ").strip()
       try:
           sniff(filter="proto ospf", prn=process_ospf_packet, store=False, iface=interface)
       except KeyboardInterrupt:
           print("\nSniffing dihentikan oleh pengguna.")

if __name__=="__main__":
       start_sniffing()
        