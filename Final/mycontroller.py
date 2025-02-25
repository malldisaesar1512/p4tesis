from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4runtime_lib.helper import P4InfoHelper
from p4runtime_lib import bmv2
import time
import sys
import threading
import grpc

#!/usr/bin/env python3

# Global variables
switch_connection = None
p4info_helper = None

def writeRegister(register_name, index, value):
    """Write value to register at specified index"""
    register_entry = p4info_helper.get_register_entry(
        register_name=register_name,
        index=index,
        data=value)
    switch_connection.WriteRegisters(register_entry)

def send_probe_packet(switch_id, ingress_port, egress_port):
    """Send probe packet and measure round trip time"""
    try:
        # Create probe packet
        packet = bytes([0xFF] * 64)  # Simple probe packet
        
        # Record start time
        start_time = time.time()
        
        # Send packet
        switch_connection.TransmitPacket(
            payload=packet,
            metadata={
                "ingress_port": ingress_port,
                "egress_port": egress_port
            }
        )
        
        # Wait for response (implement your own logic here)
        time.sleep(0.1)  # Simple delay for demonstration
        
        # Calculate round trip time
        rtt = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        # Update link status based on RTT
        if rtt <= 250:
            writeRegister("linkStatus", 0, 1)  # Link is good
            print(f"Probe successful - RTT: {rtt:.2f}ms")
        else:
            writeRegister("linkStatus", 0, 0)  # Link is bad
            print(f"Probe too slow - RTT: {rtt:.2f}ms")
            
    except grpc.RpcError as e:
        print(f"Failed to send probe: {e}")
        writeRegister("linkStatus", 0, 0)  # Link is down

def main():
    global switch_connection, p4info_helper
    
    # Initialize P4Runtime connection
    p4info_helper = P4InfoHelper('build/basic.p4.p4info.txt')
    
    try:
        # Connect to switch
        switch_connection = bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0)
        
        switch_connection.MasterArbitrationUpdate()
        
        # Main probing loop
        while True:
            send_probe_packet(0, 1, 2)  # Adjust ports as needed
            time.sleep(1)  # Probe every second
            
    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        print(f"gRPC Error: {e}")
    finally:
        ShutdownAllSwitchConnections()

if __name__ == '__main__':
    main()