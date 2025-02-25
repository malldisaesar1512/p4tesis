
import time
import sys
import os
import threading
import grpc
import subprocess
from scapy.all import sr1, IP, ICMP

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 './utils/'))
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4runtime_lib.helper import P4InfoHelper
from p4runtime_lib import bmv2

#!/usr/bin/env python3

# Global variables
switch_connection = None
p4info_helper = None

# Konfigurasi P4Runtime
SWITCH_ADDRESS = "127.0.0.1:50051"  # Ganti dengan alamat switch
REGISTER_NAME = "linkstatus"  # Nama register yang mau diatur

def set_register_value(client, register_name, index, value):
    # Buat register entry
    register_entry = p4runtime_lib.bmv2.RegisterEntry()
    register_entry.table_id = register_name
    register_entry.index = index  # Index register yang mau diatur
    register_entry.value = value

    # Set register entry
    client.SetRegisterEntry(register_entry)


if __name__ == '__main__':
    main()