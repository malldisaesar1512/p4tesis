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

# Global variable
thrift_port = 9090

# Definitions
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

def write_register(register, idx, value, thrift_port):
    p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    command = "register_write %s %d %d" % (register, idx, value)
    stdout, stderr = p.communicate(input=command.encode('utf-8'))
    if stderr:
        print("Error:", stderr.decode('utf-8'))
    return

def check_link_status(target_ip, iface):
    # Send ICMP packet to check link status
    response = srp(Ether()/IP(dst=target_ip)/ICMP(), iface=iface, timeout=1, verbose=False)[0]
    
    # If there is a response, the link is alive
    if response:
        return 1  # Link is alive
    else:
        return 0  # Link is dead

def main():
    register = "linkstatus"
    
    # Define target IPs, their corresponding interfaces, and indices
    targets = [
        {"ip": "20.20.20.2", "iface": "ens3", "index": 0},  # First target IP and interface
        {"ip": "21.21.21.2", "iface": "ens4", "index": 1}   # Second target IP and interface
    ]
    
    start_time = time.time()

    while True:
        for target in targets:
            target_ip = target["ip"]
            iface = target["iface"]
            index = target["index"]
            
            # Check link status
            link_status = check_link_status(target_ip, iface)

            if link_status == 1:
                write_register(register, index, 1, thrift_port)
                print(f"Setting register '{register}' at index '{index}' to value '{1}' for IP {target_ip} on interface {iface}")
                print("Register value set successfully.")
            else:
                write_register(register, index, 0, thrift_port)
                print(f"Setting register '{register}' at index '{index}' to value '{0}' for IP {target_ip} on interface {iface}")
                print("Register value set successfully.")

            print(f"Link status to {target_ip} on interface {iface}: {'Hidup' if link_status == 1 else 'Mati'} ({link_status})")
        
        time.sleep(1)  # Wait 1 second before sending again

if __name__ == "__main__":
    main()
