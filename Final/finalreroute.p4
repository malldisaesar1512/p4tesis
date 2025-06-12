/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
const bit<8>  TYPE_ICMP  = 1;
// const bit<8> TYPE_OSFP = 89;

const bit<1> PORT_DOWN = 1;
const bit<1> PORT_UP = 0;
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
    bit<1> var_portstatus;
    bit<9> var_portin;
    bit<48> var_macin;
    bit<32> var_ecnstatus;
    bit<48> var_rtt;
    bit<1> var_linkstatus;
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
// REGISTER DEFINITION
//------------------------------------------------------------------

register<bit<1>>(NUM_PORT) port_status;
register<bit<9>>(NUM_PORT) portin;
register<bit<9>>(NUM_PORT) portout;
register<bit<9>>(NUM_PORT) portoutnew;
register<bit<48>>(NUM_FLOW) mac_list;
register<bit<1>>(NUM_PORT) linkstatus;

register<bit<48>>(NUM_FLOW) gudangrtt;
register<bit<48>>(NUM_FLOW) flow_out;
register<bit<48>>(NUM_FLOW) flow_in;
register<bit<32>>(NUM_PORT) ecn_status;
register<bit<9>>(NUM_PORT) port_status1;
register<bit<1>>(NUM_PORT) modify_status;

//------------------------------------------------------------------
// INGRESS PROCESSING
//------------------------------------------------------------------

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    //register

    action drop() {
        mark_to_drop(standard_metadata);
    }

    // action hash_packetinout(){
    //     bit<48> var_hash_in;
    //     bit<48> var_flowid;
    //     bit<32> ip_a;
    //     bit<32> ip_b;
    //     bit<16> port_a;
    //     bit<16> port_b;
    //     bit<48> var_hash_out;

    //     if(hdr.ipv4.protocol == TYPE_ICMP && hdr.icmp.icmp_type == 8){ 
    //                 hash(var_hash_in, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, (bit<32>)NUM_FLOW);
    //                 flow_in.write((bit<32>)var_flowid, var_hash_in);
    //             }else if(hdr.ipv4.protocol == TYPE_TCP && hdr.tcp.flags == 2){
    //                 hash(var_hash_in, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort}, (bit<32>)NUM_FLOW);
    //                 flow_in.write((bit<32>)var_flowid, var_hash_in);
    //             }else if(hdr.ipv4.protocol == TYPE_UDP){
    //                 hash(var_hash_in, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort}, (bit<32>)NUM_FLOW);
    //                 flow_in.write((bit<32>)var_flowid, var_hash_in);
    //             }else{
    //                 var_hash_in = 0;
    //                 flow_in.write((bit<32>)var_flowid, var_hash_in);
    //             }

    //     if(hdr.ipv4.protocol == TYPE_ICMP && hdr.icmp.icmp_type == 0){
    //                 ip_a = hdr.ipv4.dstAddr;
    //                 ip_b = hdr.ipv4.srcAddr;

    //                 hash(var_hash_out, HashAlgorithm.crc32, (bit<32>)0, {ip_a,ip_b}, (bit<32>)NUM_FLOW);
    //                 flow_out.write((bit<32>)var_flowid, var_hash_out);
    //             }else if(hdr.ipv4.protocol == TYPE_TCP && hdr.tcp.flags == 5){
    //                 ip_a = hdr.ipv4.dstAddr;
    //                 ip_b = hdr.ipv4.srcAddr;
    //                 port_a = hdr.tcp.dstPort;
    //                 port_b = hdr.tcp.srcPort;

    //                 hash(var_hash_out, HashAlgorithm.crc32, (bit<32>)0, {ip_a, ip_b, port_a, port_b}, (bit<32>)NUM_FLOW);
    //                 flow_out.write((bit<32>)var_flowid, var_hash_out);
    //             }else if(hdr.ipv4.protocol == TYPE_UDP){
    //                 ip_a = hdr.ipv4.dstAddr;
    //                 ip_b = hdr.ipv4.srcAddr;
    //                 port_a = hdr.udp.dstPort;
    //                 port_b = hdr.udp.srcPort;

    //                 hash(var_hash_out, HashAlgorithm.crc32, (bit<32>)0, {ip_a, ip_b, port_a, port_b}, (bit<32>)NUM_FLOW);
    //                 flow_out.write((bit<32>)var_flowid, var_hash_out);
    //             }else{
    //                 var_hash_out = 0;
    //                 flow_out.write((bit<32>)var_flowid, var_hash_out);
    //             }
    // }

    // action hash_packetout(){
    //     bit<32> ip_a;
    //     bit<32> ip_b;
    //     bit<16> port_a;
    //     bit<16> port_b;
    //     bit<48> var_hash_out;
    //     bit<48> var_flowid;

    //     ip_a = hdr.ipv4.dstAddr;
    //     ip_b = hdr.ipv4.srcAddr;

    //     if(hdr.ipv4.protocol == TYPE_ICMP){ 
    //                 hash(var_hash_out, HashAlgorithm.crc32, (bit<32>)0, {ip_a, ip_b}, (bit<32>)NUM_FLOW);
    //                 flow_out.write((bit<32>)var_flowid, var_hash_out);
    //             }else if(hdr.ipv4.protocol == TYPE_TCP){
    //                 port_a = hdr.tcp.dstPort;
    //                 port_b = hdr.tcp.srcPort;
    //                 hash(var_hash_out, HashAlgorithm.crc32, (bit<32>)0, {ip_a, ip_b, port_a, port_b}, (bit<32>)NUM_FLOW);
    //                 flow_out.write((bit<32>)var_flowid, var_hash_out);
    //             }else if(hdr.ipv4.protocol == TYPE_UDP){
    //                 port_a = hdr.udp.dstPort;
    //                 port_b = hdr.udp.srcPort;
    //                 hash(var_hash_out, HashAlgorithm.crc32, (bit<32>)0, {ip_a, ip_b, port_a, port_b}, (bit<32>)NUM_FLOW);
    //                 flow_out.write((bit<32>)var_flowid, var_hash_out);
    //             }else{
    //                 var_hash_out = 0;
    //                 flow_out.write((bit<32>)var_flowid, var_hash_out);
    //             }
    // }

    // action rtt_calculation(){
    //     bit<48> var_time1;
    //     bit<48> var_time2;
    //     bit<48> var_hash_out;
    //     bit<48> var_hash_in;
    //     bit<48> var_flowid;

    //     flow_in.read(var_hash_in, (bit<32>)var_flowid);
    //     flow_out.read(var_hash_out, (bit<32>)var_flowid);
    //     if(hdr.icmp.icmp_type == 8 || hdr.tcp.flags == 2 && var_time1 == 0){
    //         gudangrtt.write((bit<32>)var_flowid, var_time1);//index,value
    //     }else if(hdr.icmp.icmp_type == 0 || hdr.tcp.flags == 5 && var_time1 != 0 && var_hash_out == var_hash_in){
    //         gudangrtt.read(var_time1, (bit<32>)var_flowid);//value,index
    //         var_time2 = standard_metadata.ingress_global_timestamp;
    //         meta.var_rtt = var_time2 - var_time1;
    //     }
    // }

    action cek_enc_status(){
        ecn_status.read(meta.var_ecnstatus,1);
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
        bit<48> var_flowid;
        bit<48> var_hash_in;
        bit<32> ip_a;
        bit<32> ip_b;
        bit<16> port_a;
        bit<16> port_b;
        bit<48> var_hash_out;
        bit<48> var_time1;
        bit<48> var_time2;
        bit<9> var_portout1;
        bit<48> var_flowmark;
        bit<48> var_threshold;
        bit<9> var_port;
        bit<9> var_portout2;

        var_flowid = 0;
        var_threshold = 250000; //refer to ITU-T G.1010


        if(hdr.ipv4.isValid()){
            if(hdr.ipv4.dstAddr == 0xffffffff || hdr.ipv4.dstAddr == 0xe0000005 || hdr.ipv4.dstAddr == 0x0b0b0102 || hdr.ipv4.dstAddr == 0x0b0b0101 || hdr.ipv4.dstAddr == 0x0a0a0101 || hdr.ipv4.dstAddr == 0x0a0a0102){ //noaction ospf dan ping
                NoAction();
            }
            else{
                if(hdr.ipv4.protocol == TYPE_ICMP && hdr.icmp.icmp_type == 8){ //hashing packet in
                    hash(var_hash_in, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, (bit<32>)NUM_FLOW);
                    flow_in.write((bit<32>)var_flowid, var_hash_in);
                }else if(hdr.ipv4.protocol == TYPE_TCP && hdr.tcp.flags == 2){
                    hash(var_hash_in, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort}, (bit<32>)NUM_FLOW);
                    flow_in.write((bit<32>)var_flowid, var_hash_in);
                }else if(hdr.ipv4.protocol == TYPE_UDP){
                    hash(var_hash_in, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort}, (bit<32>)NUM_FLOW);
                    flow_in.write((bit<32>)var_flowid, var_hash_in);
                }
                // else{
                //     var_hash_in = var_hash_out;
                //     flow_in.write((bit<32>)var_flowid, var_hash_in);
                // }

                if(hdr.ipv4.protocol == TYPE_ICMP && hdr.icmp.icmp_type == 0){ //hashing packet out
                        ip_a = hdr.ipv4.dstAddr;
                        ip_b = hdr.ipv4.srcAddr;

                        hash(var_hash_out, HashAlgorithm.crc32, (bit<32>)0, {ip_a,ip_b}, (bit<32>)NUM_FLOW);
                        flow_out.write((bit<32>)var_flowid, var_hash_out);
                    }else if(hdr.ipv4.protocol == TYPE_TCP && hdr.tcp.flags == 5){
                        ip_a = hdr.ipv4.dstAddr;
                        ip_b = hdr.ipv4.srcAddr;
                        port_a = hdr.tcp.dstPort;
                        port_b = hdr.tcp.srcPort;

                        hash(var_hash_out, HashAlgorithm.crc32, (bit<32>)0, {ip_a, ip_b, port_a, port_b}, (bit<32>)NUM_FLOW);
                        flow_out.write((bit<32>)var_flowid, var_hash_out);
                    }else if(hdr.ipv4.protocol == TYPE_UDP){
                        ip_a = hdr.ipv4.dstAddr;
                        ip_b = hdr.ipv4.srcAddr;
                        port_a = hdr.udp.dstPort;
                        port_b = hdr.udp.srcPort;

                        hash(var_hash_out, HashAlgorithm.crc32, (bit<32>)0, {ip_a, ip_b, port_a, port_b}, (bit<32>)NUM_FLOW);
                        flow_out.write((bit<32>)var_flowid, var_hash_out);
                    }
                // else{
                //     var_hash_out = var_hash_in;
                //     flow_out.write((bit<32>)var_flowid, var_hash_out);
                // }


            //rtt calculation

                flow_in.read(var_hash_in, (bit<32>)var_flowid);
                flow_out.read(var_hash_out, (bit<32>)var_flowid);
                gudangrtt.read(var_time1, (bit<32>)var_hash_in);//value,index

                if((hdr.icmp.icmp_type == 8 || hdr.tcp.flags == 2) && var_time1 == 0){
                    var_time1 = standard_metadata.ingress_global_timestamp;
                    gudangrtt.write((bit<32>)var_hash_in, var_time1);//index,value
                }else if((hdr.icmp.icmp_type == 0 || hdr.tcp.flags == 5) && (var_time1 != 0) && (var_hash_out == var_hash_in)){
                    var_time2 = standard_metadata.ingress_global_timestamp;
                    meta.var_rtt = var_time2 - var_time1;
                    var_time1 = 0;
                    meta.var_portin = standard_metadata.ingress_port;
                    portin.write((bit<32>)var_flowid, meta.var_portin);
                    gudangrtt.write((bit<32>)var_hash_out, var_time1);
                    gudangrtt.write((bit<32>)var_flowid, meta.var_rtt);
                }
                
                gudangrtt.read(meta.var_rtt, (bit<32>)var_flowid);
                cek_enc_status();
                linkstatus.read(meta.var_linkstatus,0);
                if(meta.var_rtt == 0){
                    gudangrtt.write((bit<32>)var_flowid,0);
                    port_status.write(0, PORT_UP);
                }
                else{
                    portin.read(meta.var_portin, (bit<32>)var_flowid);
                    portout.read(var_portout1, (bit<32>)var_flowid);
                    if((meta.var_rtt >= var_threshold) || (meta.var_ecnstatus == 3) || (meta.var_linkstatus == 1)){
                        port_status.read(meta.var_portstatus,0);
                        // modify_status.write(0, 1);
                        if((meta.var_portstatus == PORT_DOWN) || (meta.var_linkstatus == 1)){
                            port_status.write(0, PORT_UP);   
                        }
                        else if((meta.var_portstatus == PORT_UP) || (meta.var_linkstatus == 0)){
                            port_status.write(0, PORT_DOWN);
                        }
                    }
                    else if(meta.var_rtt <= var_threshold && meta.var_ecnstatus == 0 && meta.var_linkstatus == 0){
                        port_status.read(meta.var_portstatus,0);
                        // modify_status.write(0, 0);
                        if(meta.var_portstatus == PORT_DOWN){
                            port_status.write(0, PORT_DOWN);   
                        }else{
                            port_status.write(0, PORT_UP);
                        }
                    }
                }

                //decision
                port_status.read(meta.var_portstatus,0);    
                if(meta.var_portstatus == PORT_DOWN){
                    ipv4_reroute.apply();
                    var_portout1 = 2;
                    var_portout2 = standard_metadata.egress_spec;
                    portout.write((bit<32>)var_flowid, var_portout1);
                    portoutnew.write(0, var_portout2);
                    port_status.write(0, PORT_DOWN);
                    modify_status.write(0, 1);
                }
                else{
                    ipv4_lpm.apply();
                    var_portout1 = 1;
                    var_portout2 = standard_metadata.egress_spec;
                    portout.write((bit<32>)var_flowid, var_portout1);
                    portoutnew.write(0, var_portout2);
                    port_status.write(0, PORT_UP);
                    modify_status.write(0, 0);
                }
            }
        }
                
        else{
            drop();
        }
    }
}

//------------------------------------------------------------------
// EGRESS PROCESSING
//------------------------------------------------------------------

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    
    action mark_ecn() {
        hdr.ipv4.ecn = 3;
        meta.var_ecnstatus = 3;
        ecn_status.write(1, meta.var_ecnstatus);

    }
    apply { 
        if (hdr.ipv4.ecn == 1 || hdr.ipv4.ecn == 2){
            if (standard_metadata.enq_qdepth >= ECN_THRESHOLD){ //ecn marking
                mark_ecn();
            }else{
                hdr.ipv4.ecn = 0;
                meta.var_ecnstatus = 0;
                ecn_status.write(1, meta.var_ecnstatus);
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