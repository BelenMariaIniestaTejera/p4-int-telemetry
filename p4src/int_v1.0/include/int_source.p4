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

// Registro para el numero de secuencia de cabeceras INT
#ifdef BMV2
register<bit<16>> (1) hdr_seq_num_register;
#elif TOFINO
Register<bit<16>, bit<16>>(1) hdr_seq_num_register;
RegisterAction<bit<16>, bit<16>, bit<16>>(hdr_seq_num_register)
    update_hdr_seq_num = {
        void apply(inout bit<16> value, out bit<16> result) {
            result = value;
            value = value + 1;
        }
    };
#endif

#ifdef BMV2

control Int_source(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

#elif TOFINO

control Int_source(inout headers hdr, inout metadata meta, in ingress_intrinsic_metadata_t standard_metadata, in ingress_intrinsic_metadata_from_parser_t imp) {

#endif

    // Configura los parametros del nodo INT source:
    // max_hop           - cuantos nodos INT pueden anadir su metadata
    // hop_metadata_len  - palabras de 4 bytes que anade un nodo INT
    // ins_cnt           - numero de cabeceras INT que anade un nodo
    // ins_mask          - instruction_mask: que tipos de metadata INT se incluyen
    action configure_source(bit<8> max_hop, bit<5> hop_metadata_len, bit<5> ins_cnt, bit<16> ins_mask) {
        hdr.int_shim.setValid();
        hdr.int_shim.int_type = INT_TYPE_HOP_BY_HOP;
        hdr.int_shim.len = (bit<8>)INT_ALL_HEADER_LEN_BYTES >> 2;
        
        hdr.int_header.setValid();
        hdr.int_header.ver = INT_VERSION;
        hdr.int_header.rep = 0;
        hdr.int_header.c = 0;
        hdr.int_header.e = 0;
        hdr.int_header.m = 0;
        hdr.int_header.rsvd1 = 0;
        hdr.int_header.rsvd2 = 0;
        hdr.int_header.hop_metadata_len = hop_metadata_len;
        hdr.int_header.remaining_hop_cnt = max_hop;
        hdr.int_header.instruction_mask = ins_mask;

#ifdef BMV2
        hdr_seq_num_register.read(hdr.int_header.seq, 0);
        hdr_seq_num_register.write(0, hdr.int_header.seq + 1);
#elif TOFINO
        hdr.int_header.seq = update_hdr_seq_num.execute(0);
#endif

        // Guardar DSCP original en el shim y marcar el paquete como INT
        hdr.int_shim.dscp = hdr.ipv4.dscp;
        hdr.ipv4.dscp = IPv4_DSCP_INT;

        // Actualizar longitud total IPv4 con el tamano de las cabeceras INT anadidas
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + INT_ALL_HEADER_LEN_BYTES;
        
        // Actualizar campo len de UDP si el paquete es UDP
        // ICMP no tiene campo len propio: solo se actualiza totalLen del IPv4 (hecho arriba)
        if (hdr.udp.isValid()) {
            hdr.udp.len = hdr.udp.len + INT_ALL_HEADER_LEN_BYTES;
        }
        
        // FIX ICMP: antes aqui se ponia hdr.icmp.checksum = 16w0 a mano,
        // dejando un checksum invalido (a diferencia de UDP, en ICMP
        // checksum=0 no es un valor valido). Ya no hace falta tocarlo:
        // se recalcula correctamente en el bloque computeChecksum
        // (ver include/parser.p4), igual que para IPv4 y UDP.
    }

    // Tabla INT source: define que flujos deben ser monitorizados con INT.
    // Un flujo se identifica por: IP src, IP dst, protocolo L4, puerto src, puerto dst.
    // Para ICMP: l4_proto=0x01, l4_src=0, l4_dst=0 (ICMP no tiene puertos).
    // Se usa matching ternary para poder usar mascaras (ej: cualquier puerto).
    table tb_int_source {
        actions = {
            configure_source;
        }
        key = {
            hdr.ipv4.srcAddr                    : ternary;
            hdr.ipv4.dstAddr                    : ternary;
            meta.layer34_metadata.l4_proto      : ternary;
            meta.layer34_metadata.l4_src        : ternary;
            meta.layer34_metadata.l4_dst        : ternary;
        }
        size = 127;
    }


    action activate_source() {
        meta.int_metadata.source = 1;
    }
    
    // Tabla para activar INT source en un puerto de ingreso del switch
    table tb_activate_source {
        actions = {
            activate_source;
        }
        key = {
            standard_metadata.ingress_port: exact;
        }
        size = 255;
    }


    apply {
        #ifdef BMV2
        meta.int_metadata.ingress_tstamp = standard_metadata.ingress_global_timestamp;
        meta.int_metadata.ingress_port = (bit<16>)standard_metadata.ingress_port;
        #elif TOFINO
        meta.int_metadata.setValid();
        meta.int_metadata.ingress_tstamp = imp.global_tstamp;
        meta.int_metadata.ingress_port = (bit<16>)standard_metadata.ingress_port;
        #endif

        // Comprobar si el paquete llego por un puerto con INT source activo
        tb_activate_source.apply();
        
        if (meta.int_metadata.source == 1)      
            // Aplicar logica INT source al flujo monitorizado
            tb_int_source.apply();
    }
}
