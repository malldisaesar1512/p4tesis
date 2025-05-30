import struct
import time
import p4runtime_sh.shell as sh

def int_to_ip(addr):
    return '.'.join(str((addr >> (8 * i)) & 0xFF) for i in reversed(range(4)))

def parse_ipv4(pkt):
    if len(pkt) < 34:
        return None
    eth_type = struct.unpack('!H', pkt[12:14])[0]
    if eth_type != 0x0800:
        return None

    proto = pkt[23]
    src_ip = struct.unpack('!I', pkt[26:30])[0]
    dst_ip = struct.unpack('!I', pkt[30:34])[0]
    return {
        "proto": proto,
        "src_ip": int_to_ip(src_ip),
        "dst_ip": int_to_ip(dst_ip)
    }

def main():
    sh.setup(
        device_id=0,
        grpc_addr='0.0.0.0:9559',
        election_id=(0, 1),
        config=sh.FwdPipeConfig('./p4runtime.p4info.txtpb', './finalospf.json')
    )

    pktin_receiver = sh.PacketIn()

    print("📥 Terhubung ke switch. Menunggu packet-in...\n")

    while True:
        pktin = pktin_receiver.recv(timeout=1.0)
        if pktin is None:
            continue

        pkt = pktin.payload
        info = parse_ipv4(pkt)

        if info is None:
            print("⚠️  Non-IPv4 atau paket tidak valid\n")
            continue

        proto = info["proto"]
        proto_str = {
            1: "ICMP",
            89: "OSPF"
        }.get(proto, "Other")

        print("📦 Packet-In:")
        print(f"  ➤ Src IP : {info['src_ip']}")
        print(f"  ➤ Dst IP : {info['dst_ip']}")
        print(f"  ➤ Proto  : {proto} ({proto_str})\n")

if __name__ == "__main__":
    main()
