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
const bit<19> ECN_THRESHOLD = 10;
// const bit<32> NUM_OFFSET = 100;

//------------------------------------------------------------------
// HEADER DEFINITIONS
//------------------------------------------------------------------

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
    bit<6>    diffserv;
    bit<2>    ecn;
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
    bit<8>  flags;
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

//------------------------------------------------------------------
// PARSER DEFINITION
//------------------------------------------------------------------

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

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            TYPE_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

}

//------------------------------------------------------------------
// CHECKSUM VERIFICATION
//------------------------------------------------------------------

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

//------------------------------------------------------------------
// INGRESS PROCESSING
//------------------------------------------------------------------

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    //register
    register<bit<1>>(NUM_PORT) port_status;
    register<bit<9>>(NUM_PORT) portin;
    register<bit<48>>(NUM_FLOW) mac_list;

    register<bit<48>>(NUM_FLOW) gudangrtt;
    register<bit<32>>(NUM_FLOW) flow_id;


    action drop() {
        mark_to_drop(standard_metadata);
    }

    action hash_packetin(){
        if(hdr.ipv4.protocol == TYPE_ICMP){ 
                    hash(var_hash_in, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, (bit<32>)NUM_FLOW);
                    flow_id.write((bit<32>)var_flowid, var_hash_in);
                }else if(hdr.ipv4.protocol == TYPE_TCP){
                    hash(var_hash_in, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort}, (bit<32>)NUM_FLOW);
                    flow_id.write((bit<32>)var_flowid, var_hash_in);
                }else if(hdr.ipv4.protocol == TYPE_UDP){
                    hash(var_hash_in, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort}, (bit<32>)NUM_FLOW);
                    flow_id.write((bit<32>)var_flowid, var_hash_in);
                }else{
                    var_hash_in = 0;
                    flow_id.write((bit<32>)var_flowid, var_hash_in);
                }
    }

    action hash_packetout(){
        if(hdr.ipv4.protocol == TYPE_ICMP){ 
                    hash(var_hash_out, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, (bit<32>)NUM_FLOW);
                    flow_id.read((bit<32>)var_flowid, var_hash_out);
                }else if(hdr.ipv4.protocol == TYPE_TCP){
                    hash(var_hash_out, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort}, (bit<32>)NUM_FLOW);
                    flow_id.read((bit<32>)var_flowid, var_hash_out);
                }else if(hdr.ipv4.protocol == TYPE_UDP){
                    hash(var_hash_out, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort}, (bit<32>)NUM_FLOW);
                    flow_id.read((bit<32>)var_flowid, var_hash_out);
                }else{
                    var_hash_out = 0;
                    flow_id.read((bit<32>)var_flowid, var_hash_out);
                }
    }

    action rtt_calculation(){
        if(hdr.icmp.icmp_type == 8 || hdr.tcp.flags == 2 && var_time1 == 0){
            gudangrtt.write(var_flowid, var_time1);//index,value
        }else if(hdr.icmp.icmp_type == 0 || hdr.tcp.flags == 5 && var_time1 != 0){
            gudangrtt.read(var_time1, var_flowid);//value,index
            var_time2 = standard_metadata.ingress_global_timestamp;
            var_rtt = var_time2 - var_time1;
        }
    }

    action cek_enc_status(){
        enc_status.read(var_ecnstatus,1);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ipv4_rerouting(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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
        //variabel
        bit<1> var_portstatus;
        bit<9> var_portin;
        bit<48> var_macin;
        bit<48> var_flowid;
        bit<48> var_hash_in;
        bit<48> var_hash_out;
        bit<48> var_time1;
        bit<48> var_time2;
        bit<32> var_ecnstatus;


        if(hdr.ipv4.isValid()){
            if(hdr.ipv4.protocol == TYPE_ICMP){
                if(hdr.icmp.icmp_type == 8){
                    hash_packetin();
                    rtt_calculation();
                }else if(hdr.icmp.icmp_type == 0){
                    hash_packetout();
                    rtt_calculation();
                }
            }else if(hdr.ipv4.protocol == TYPE_TCP){
                if(hdr.tcp.flags == 2){
                    hash_packetin();
                    rtt_calculation();
                }else if(hdr.tcp.flags == 5){
                    hash_packetout();
                    rtt_calculation();
                }
            }else if(hdr.ipv4.protocol == TYPE_UDP){
            
            }
            
            ipv4_lpm.apply();              
        }
        else{
            ipv4_reroute.apply();
        }
    }
}

//------------------------------------------------------------------
// EGRESS PROCESSING
//------------------------------------------------------------------

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    register<bit<32>>(ECN_THRESHOLD) enc_status;
    
    action mark_ecn() {
        hdr.ipv4.ecn = 3;
        enc_status.write(1, hdr.ipv4.ecn);

    }
    apply { 
        if (hdr.ipv4.ecn == 1 || hdr.ipv4.ecn == 2){
            if (standard_metadata.enq_qdepth >= ECN_THRESHOLD){
                mark_ecn();
            }else{
                hdr.ipv4.ecn = 0;
            }
        }
     }
}

//------------------------------------------------------------------
// Checksum computation
//------------------------------------------------------------------

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.ecn,
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

//------------------------------------------------------------------
// DEPARSER DEFINITION
//------------------------------------------------------------------

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

//------------------------------------------------------------------
// SWITCH
//------------------------------------------------------------------

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;