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
            8w0x1:  parse_icmp;   // ICMP: protocolo IP numero 1
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

    // Estado ICMP: no tiene puertos L4, se ponen a 0 para que
    // tb_int_source pueda usar ternary matching con mascara 0x0000
    state parse_icmp {
        packet.extract(hdr.icmp);
        meta.layer34_metadata.l4_proto = 8w0x1;
        meta.layer34_metadata.l4_src = 0;
        meta.layer34_metadata.l4_dst = 0;
        // ICMP con INT: solo si el DSCP indica paquete INT
        transition select(meta.layer34_metadata.dscp) {
            IPv4_DSCP_INT: parse_int;
            default: accept;
        }
    }

    state parse_int {
        packet.extract(hdr.int_shim);
        packet.extract(hdr.int_header);
        // ARREGLO metadata acumulada: todo lo que venga detras de shim+header
        // (es decir, la metadata que ya anadieron switches anteriores) se
        // extrae aqui como un bloque con nombre (hdr.int_data), en vez de
        // dejarlo como payload sin identificar. Asi el sink SI puede
        // invalidarlo/borrarlo mas adelante (ver int_sink.p4).
        // int_shim.len viene en palabras de 4 bytes; le restamos el tamano
        // fijo de shim+header (INT_ALL_HEADER_LEN_BYTES = 12 bytes) para
        // saber cuantos bytes de metadata previa quedan por delante.
        bit<16> prev_hops_bytes = (((bit<16>)hdr.int_shim.len) << 2) - INT_ALL_HEADER_LEN_BYTES;
        packet.extract(hdr.int_data, (bit<32>)prev_hops_bytes * 8);
        transition accept;
    }
}

#ifdef BMV2
control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        // Cabeceras del reporte INT (solo validas en paquetes clonados en el sink)
        packet.emit(hdr.report_ethernet);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.report_fixed_header);
        
        // Cabeceras originales del paquete
        // ORDEN IMPORTANTE: ethernet -> ipv4 -> [tcp | udp | icmp] -> INT headers
        // Solo se emite el header valido (tcp, udp o icmp son mutuamente excluyentes)
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
        
        // Cabeceras INT (van despues del transporte, antes del payload)
        packet.emit(hdr.int_shim);
        packet.emit(hdr.int_header);
        
        // Metadata INT del nodo local
        packet.emit(hdr.int_switch_id);            // bit 1
        packet.emit(hdr.int_port_ids);             // bit 2
        packet.emit(hdr.int_hop_latency);          // bit 3
        packet.emit(hdr.int_q_occupancy);          // bit 4
        packet.emit(hdr.int_ingress_tstamp);       // bit 5
        packet.emit(hdr.int_egress_tstamp);        // bit 6
        packet.emit(hdr.int_level2_port_ids);      // bit 7
        packet.emit(hdr.int_egress_port_tx_util);  // bit 8
        packet.emit(hdr.int_pkt_len);

        // ARREGLO metadata acumulada: aqui va, a continuacion de la metadata
        // que ha anadido ESTE switch, el bloque con los hops anteriores que
        // extrajimos en el parser (hdr.int_data). Si el sink lo invalida
        // (int_sink.p4), el deparser simplemente no lo emite, y desaparece
        // de verdad en vez de quedar como bytes sueltos sin dueno.
        packet.emit(hdr.int_data);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // ---------------------------------------------------------------
        // Checksum IPv4 del paquete original
        // ---------------------------------------------------------------
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
        
        // ---------------------------------------------------------------
        // Checksum IPv4 del paquete de reporte INT
        // ---------------------------------------------------------------
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
        
        // ---------------------------------------------------------------
        // Checksum UDP sin INT
        // ---------------------------------------------------------------
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

        // ---------------------------------------------------------------
        // Checksum UDP con datos INT
        // ---------------------------------------------------------------
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

        // ---------------------------------------------------------------
        // FIX ICMP: checksum ICMP sin INT.
        // A diferencia de UDP, ICMP NO lleva pseudo-cabecera IP (no se
        // incluyen srcAddr/dstAddr en el calculo). El campo checksum cubre
        // el resto de la cabecera ICMP + los datos (el "payload" del ping)
        // se anade automaticamente por update_checksum_with_payload.
        // Antes, int_source.p4 e int_sink.p4 ponian este campo a 0 a mano;
        // ahora se recalcula aqui correctamente, igual que ya se hacia con
        // IPv4 y UDP.
        // ---------------------------------------------------------------
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

        // ---------------------------------------------------------------
        // FIX ICMP: checksum ICMP con datos INT (mismo caso que arriba,
        // pero incluyendo tambien las cabeceras INT anadidas, igual que
        // se hace para UDP+INT).
        // ---------------------------------------------------------------
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
// ... (codigo Tofino sin cambios)
#endif
