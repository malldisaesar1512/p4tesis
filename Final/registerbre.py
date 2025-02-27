import argparse
import sys
import socket
import random
import struct

import subprocess
import time 
from datetime import datetime



from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP


#variabel global
thrift_port = 9559

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
    stdout, stderr = p.communicate(input="register_write %s %d %d" % (register, idx, value))
    #reg_val = [l for l in stdout.split('\n') if ' %s[%d]' % (register, idx) in l][0].split('= ', 1)[1]
    return

def main():

    print(f"Setting register linkstatus at index 0 to value 1")
    write_register("linkstatus", 0, 1, thrift_port)

    print("Register value set successfully.")

if __name__ == "__main__":
    main()