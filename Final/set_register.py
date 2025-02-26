
import grpc
import sys
import os

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 './utils/'))
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4runtime_lib.helper import P4InfoHelper
from p4runtime_lib import bmv2

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

def main():
    # Buat koneksi ke switch
    switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s1',
        address=SWITCH_ADDRESS,
        device_id=0
    )

    # Connect ke switch
    switch.MasterArbitration()

    # Input nilai ke register
    index = int(input("Masukkan index register yang ingin diatur: "))  # Input index register
    value = int(input("Masukkan nilai yang ingin diinput ke register: "))  # Input nilai register

    print(f"Setting register '{REGISTER_NAME}' at index {index} to value {value}")
    set_register_value(switch, REGISTER_NAME, index, value)

    print("Register value set successfully.")

    # Shutdown all switch connections
    ShutdownAllSwitchConnections()

if __name__ == "__main__":
    main()
