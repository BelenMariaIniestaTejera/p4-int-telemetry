/*
 * Copyright 2020-2021 PSNC, FBK
 *
 * Author: Damian Parniewicz, Damu Ding
 *
 * Created in the GN4-3 project.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

error
{
	INTShimLenTooShort,
	INTVersionNotSupported
}

#ifdef BMV2
parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
       transition parse_ethernet;
    }
#elif TOFINO
parser IngressParser(packet_in packet, out headers hdr, out metadata meta, out ingress_intrinsic_metadata_t standard_metadata) {
    Checksum() ipv4_checksum;
    state start {
        packet.extract(standard_metadata);
        packet.advance(PORT_METADATA_SIZE);
        meta.int_metadata.mirror_type = 0;
        meta.int_metadata.session_ID = 1;
        meta.int_metadata.source = 0;
        meta.int_metadata.sink = 0;
        meta.int_metadata.switch_id = 0;
        meta.int_metadata.insert_byte_cnt = 0;
        meta.int_metadata.int_hdr_word_len = 0;
        meta.int_metadata.remove_int = 0;
        meta.int_metadata.sink_reporting_port = 0;
        meta.int_metadata.ingress_port = 0;
        meta.layer34_metadata.ip_src = 0;
        meta.layer34_metadata.ip_dst = 0;
        meta.layer34_metadata.ip_ver = 0;
        meta.layer34_metadata.l4_src = 0;
        meta.layer34_metadata.l4_dst = 0;
        meta.layer34_metadata.l4_proto = 0;
        meta.layer34_metadata.l3_mtu = 0;
        meta.layer34_metadata.dscp = 0;
        meta.int_len_bytes = 0;
        transition parse_ethernet;
    }
#endif

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.layer34_metadata.ip_src = hdr.ipv4.srcAddr;
        meta.layer34_metadata.ip_dst = hdr.ipv4.dstAddr;
        meta.layer34_metadata.ip_ver = 8w4;
        meta.layer34_metadata.dscp = hdr.ipv4.dscp;

        #ifdef TOFINO
        ipv4_checksum.add(hdr.ipv4);
        ipv4_checksum.verify();
        #endif

        transition select(hdr.ipv4.protocol) {
            8w0x11: parse_udp;
            8w0x6:  parse_tcp;
            8w0x1:  parse_icmp;    // ICMP protocol number
            default: accept;
        }
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.layer34_metadata.l4_src = hdr.tcp.srcPort;
        meta.layer34_metadata.l4_dst = hdr.tcp.dstPort;
        meta.layer34_metadata.l4_proto = 8w0x6;
        transition select(meta.layer34_metadata.dscp) {
            IPv4_DSCP_INT: parse_int;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.layer34_metadata.l4_src = hdr.udp.srcPort;
        meta.layer34_metadata.l4_dst = hdr.udp.dstPort;
        meta.layer34_metadata.l4_proto = 8w0x11;
        transition select(meta.layer34_metadata.dscp, hdr.udp.dstPort) {
            (6w0x20 &&& 6w0x3f, 16w0x0 &&& 16w0x0): parse_int;
            default: accept;
        }
    }

    // ICMP has no L4 ports, so source and destination ports are set to zero.
    state parse_icmp {
        packet.extract(hdr.icmp);
        meta.layer34_metadata.l4_proto = 8w0x1;
        meta.layer34_metadata.l4_src = 0;
        meta.layer34_metadata.l4_dst = 0;
        // Parse INT headers only when the DSCP value indicates an INT packet.
        transition select(meta.layer34_metadata.dscp) {
            IPv4_DSCP_INT: parse_int;
            default: accept;
        }
    }

    state parse_int {
        packet.extract(hdr.int_shim);
        packet.extract(hdr.int_header);
        // Extract previously accumulated INT metadata dynamically.
		// int_shim.len is expressed in 4-byte words.
        bit<16> prev_hops_bytes = (((bit<16>)hdr.int_shim.len) << 2) - INT_ALL_HEADER_LEN_BYTES;
        packet.extract(hdr.int_data, (bit<32>)prev_hops_bytes * 8);
        transition accept;
    }
}

#ifdef BMV2
control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        // INT report headers
        packet.emit(hdr.report_ethernet);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.report_fixed_header);
        
        // Original packet headers
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
        
        // INT headers
        packet.emit(hdr.int_shim);
        packet.emit(hdr.int_header);
        
        // Local INT metadata
        packet.emit(hdr.int_switch_id);            
        packet.emit(hdr.int_port_ids);             
        packet.emit(hdr.int_hop_latency);          
        packet.emit(hdr.int_q_occupancy);          
        packet.emit(hdr.int_ingress_tstamp);       
        packet.emit(hdr.int_egress_tstamp);       
        packet.emit(hdr.int_level2_port_ids);      
        packet.emit(hdr.int_egress_port_tx_util);  
        packet.emit(hdr.int_pkt_len);

        // Emit previously accumulated INT metadata.
        packet.emit(hdr.int_data);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // Original packet IPv4 checksum
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.id,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        
        // INT report IPv4 checksum
        update_checksum(
            hdr.report_ipv4.isValid(),
            {
                hdr.report_ipv4.version,
                hdr.report_ipv4.ihl,
                hdr.report_ipv4.dscp,
                hdr.report_ipv4.ecn,
                hdr.report_ipv4.totalLen,
                hdr.report_ipv4.id,
                hdr.report_ipv4.flags,
                hdr.report_ipv4.fragOffset,
                hdr.report_ipv4.ttl,
                hdr.report_ipv4.protocol,
                hdr.report_ipv4.srcAddr,
                hdr.report_ipv4.dstAddr
            },
            hdr.report_ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        
        // UDP checksum without INT
        update_checksum_with_payload(
            hdr.udp.isValid() && !hdr.int_header.isValid(),
            {
                hdr.ipv4.srcAddr, 
                hdr.ipv4.dstAddr, 
                8w0, 
                hdr.ipv4.protocol, 
                hdr.udp.len, 
                hdr.udp.srcPort, 
                hdr.udp.dstPort, 
                hdr.udp.len 
            }, 
            hdr.udp.csum, 
            HashAlgorithm.csum16
        ); 

        // UDP checksum with INT
        update_checksum_with_payload(
            hdr.udp.isValid() && hdr.int_header.isValid(),
            {
                hdr.ipv4.srcAddr, 
                hdr.ipv4.dstAddr, 
                8w0, 
                hdr.ipv4.protocol, 
                hdr.udp.len, 
                hdr.udp.srcPort, 
                hdr.udp.dstPort, 
                hdr.udp.len,
                hdr.int_shim,
                hdr.int_header,
                hdr.int_switch_id,
                hdr.int_port_ids,
                hdr.int_q_occupancy,
                hdr.int_level2_port_ids,
                hdr.int_ingress_tstamp,
                hdr.int_egress_tstamp,
                hdr.int_egress_port_tx_util,
                hdr.int_hop_latency
            }, 
            hdr.udp.csum, 
            HashAlgorithm.csum16
        );

        // ICMP checksum without INT
        update_checksum_with_payload(
            hdr.icmp.isValid() && !hdr.int_header.isValid(),
            {
                hdr.icmp.type,
                hdr.icmp.code,
                hdr.icmp.rest
            },
            hdr.icmp.checksum,
            HashAlgorithm.csum16
        );

       // ICMP checksum with INT metadata
        update_checksum_with_payload(
            hdr.icmp.isValid() && hdr.int_header.isValid(),
            {
                hdr.icmp.type,
                hdr.icmp.code,
                hdr.icmp.rest,
                hdr.int_shim,
                hdr.int_header,
                hdr.int_switch_id,
                hdr.int_port_ids,
                hdr.int_q_occupancy,
                hdr.int_level2_port_ids,
                hdr.int_ingress_tstamp,
                hdr.int_egress_tstamp,
                hdr.int_egress_port_tx_util,
                hdr.int_hop_latency
            },
            hdr.icmp.checksum,
            HashAlgorithm.csum16
        );

    }
}

#elif TOFINO
// Tofino implementation unchanged.
#endif
