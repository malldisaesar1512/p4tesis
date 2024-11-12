/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
const bit<8>  TYPE_ICMP  = 1;

const bit<1> PORT_DOWN = 0;
const bit<1> PORT_UP = 1;
const bit<32> NUM_PORT = 4;
const bit<32> NUM_FLOW = 100000;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<8> icmp_type;
    bit<8> icmp_code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
    bit<64> timestamp;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
    icmp_t       icmp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    // state parse_ipv4 {
    //     packet.extract(hdr.ipv4);
    //     transition accept;
    // }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_ICMP: parse_icmp;
            TYPE_UDP: parse_udp;
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<1>>(NUM_PORT) portstatus;
    register<bit<9>>(NUM_FLOW) portin;
    register<bit<48>>(NUM_FLOW) macin;
    register<bit<48>>(NUM_FLOW) flow_time;
    register<bit<48>>(NUM_PORT) trigger;
    register<bit<48>>(NUM_PORT) gudangrtt;
    

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ipv4_rerouting(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table ipv4_reroute{
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_rerouting;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
            
            bit<1> var_portstatus;
            bit<9> var_portin;
            bit<48> var_macin;
            bit<48> var_flowtime;
            bit<48> var_hash_port_keluar;
            bit<1> var_hash_port_in;
            bit<48> var_hash_mac_in;
            bit<48> var_trigger;
            bit<48> var_t1;
            bit<48> var_t2;
            bit<48> var_rtt;
            bit<48> var_threshold;
            bit<48> var_index1;
            bit<48> var_index2;
            
            var_threshold = 500;
            var_index1 = 0;
            var_index2 = 1;
            var_portstatus = 0;

        if (hdr.ipv4.isValid()) {
            if(hdr.ipv4.protocol == TYPE_ICMP){
                hash(var_hash_port_in, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, (bit<32>)NUM_PORT);
            }
            if(hdr.ipv4.protocol == TYPE_TCP){
                hash(var_hash_port_in, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort}, (bit<32>)NUM_PORT);
            }
            if(hdr.ipv4.protocol == TYPE_UDP){
                hash(var_hash_port_in, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort}, (bit<32>)NUM_PORT);
            }
            else{
                var_hash_port_in = 0;
            }

            portin.read(var_portin,(bit<32>)var_hash_port_in);
            if(var_hash_port_in == 0){
                portin.write((bit<32>)var_hash_port_in,standard_metadata.ingress_port);
                macin.write((bit<32>)var_hash_mac_in,hdr.ethernet.srcAddr);
                var_portin = standard_metadata.ingress_port;
            }

            gudangrtt.read(var_t1,(bit<32>)var_index1);
            if(hdr.ipv4.ttl>0){
               if(var_t1 == 0){
                gudangrtt.write((bit<32>)var_t1,standard_metadata.ingress_global_timestamp);
                gudangrtt.read(var_t1,(bit<32>)var_index1);
               }
               else{
                var_t2 = standard_metadata.ingress_global_timestamp;
                var_rtt = var_t2 - var_t1;

                gudangrtt.write((bit<32>)var_rtt, var_index2);

                gudangrtt.write((bit<32>)var_t1,0);
               }

            }

            gudangrtt.read(var_rtt, (bit<32>)var_index2);
            if(var_rtt == 0){
                gudangrtt.write((bit<32>)var_rtt, 1);
            }
            else{
                if(var_rtt > var_threshold){
                    portstatus.write((bit<32>)var_portstatus, PORT_DOWN);
                }
            }

            portstatus.read(var_portstatus,(bit<32>)standard_metadata.egress_spec);    
            if(var_portstatus == PORT_DOWN){
                ipv4_reroute.apply();
            }
            else{
                ipv4_lpm.apply();
            }
        }
    }
}

/* register_write portstatus (PORT) (PORTSTATUS 0|1)*/

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
