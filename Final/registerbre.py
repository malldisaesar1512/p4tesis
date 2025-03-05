import argparse
from atexit import register
from operator import index
import sys
import socket
import random
import struct

import subprocess
import time 
from datetime import datetime



from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, ICMP, srp


#variabel global
thrift_port = 9090

#definisi
def read_registerAll(register, thrift_port):
    p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(input="register_read %s" % (register))
    reg_val = [l for l in stdout.split('\n') if ' %s' % (register) in l][0].split('= ', 1)[1]
    return reg_val.split(", ")

def read_register(register, idx, thrift_port):
    p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(input="register_read %s %d" % (register, idx))
    reg_val = [l for l in stdout.split('\n') if ' %s[%d]' % (register, idx) in l][0].split('= ', 1)[1]
    return int(reg_val)

def write_register(register, idx, value ,thrift_port):
    p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    command = "register_write %s %d %d" % (register, idx, value)
    stdout, stderr = p.communicate(input=command.encode('utf-8'))
    #reg_val = [l for l in stdout.split('\n') if ' %s[%d]' % (register, idx) in l][0].split('= ', 1)[1]
    if stderr:
        print("Error:", stderr.decode('utf-8'))

    return

def check_link_status(srcmac, dstmac, from_ip, target_ip, iface):
    # Kirim paket ICMP untuk mengecek status link
    response = srp(Ether(src=srcmac,dst=dstmac)/IP(src=from_ip,dst=target_ip)/ICMP(), iface=iface, timeout=1, verbose=False)[0]
    
    # Jika ada balasan, link hidup
    if response:
        return 1  # Link hidup
    else:
        return 0  # Link mati

def main():
    register = "linkstatus"
    srcmac = "50:00:00:00:01:00"
    dstmac = "50:00:00:00:02:01"
    index = 0
    from_ip = "11.11.11.1"
    target_ip = "20.20.20.2"  # Ganti dengan IP target yang mau dikirimi hello packet
    iface = "ens5"  # Ganti dengan nama interface yang mau dipake
    prev_linkstatus = -1
    start_time = time.time()

    while True:
        # Cek status link
        link_status = check_link_status(srcmac, dstmac, from_ip, target_ip, iface)
        if link_status != prev_linkstatus:
            if link_status == 1:
                write_register(register, index, 1, thrift_port)
                print(f"Setting register '{register}' at index '{index}' to value '{1}'' ")
                print("Register value set successfully.")
            else:
                write_register(register, index, 0, thrift_port)
                print(f"Setting register '{register}' at index '{index}' to value '{0}'' ")
                print("Register value set successfully.")

        print(f"Link status to {target_ip}: {'Hidup' if link_status == 1 else 'Mati'} ({link_status})")
        
        prev_linkstatus = link_status

        time.sleep(1)  # Tunggu 1 detik sebelum mengirim lagi

if __name__ == "__main__":
    main()