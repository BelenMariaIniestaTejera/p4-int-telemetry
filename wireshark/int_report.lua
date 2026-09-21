-- int_report.lua
-- Disector de Wireshark para los reportes INT del proyecto GEANT int-platforms
-- (mismo formato que interpreta utils/int_collector_influx.py).
--
-- INSTALACION:
--   Copiar este fichero en tu carpeta de plugins Lua personales de Wireshark:
--     Ayuda -> Acerca de Wireshark -> pestana "Folders" -> "Personal Lua Plugins"
--   (normalmente: %APPDATA%\Wireshark\plugins en Windows,
--                 ~/.local/lib/wireshark/plugins en Linux,
--                 ~/.config/wireshark/plugins en Mac)
--   Luego reinicia Wireshark (o Analyze -> Reload Lua Plugins).
--
-- Por defecto se activa para el trafico UDP con puerto de destino 6000


local int_report_proto = Proto("intreport", "INT Report (GEANT int-platforms)")

----------------------------------------------------------------------------
-- Campos: report_fixed_header (16 bytes)
----------------------------------------------------------------------------
local f_rep_ver          = ProtoField.uint8("intreport.ver", "Version", base.DEC, nil, 0xF0)
local f_rep_len          = ProtoField.uint8("intreport.len", "Len (header words)", base.DEC, nil, 0x0F)
local f_rep_nprot        = ProtoField.uint8("intreport.nprot", "Nprot", base.DEC)
local f_rep_switch_id    = ProtoField.uint32("intreport.switch_id", "Switch ID (del sink que genero el reporte)", base.DEC)
local f_rep_seq_num      = ProtoField.uint32("intreport.seq_num", "Seq Num", base.DEC)
local f_rep_ingress_ts   = ProtoField.uint32("intreport.ingress_tstamp", "Ingress Timestamp (report hdr)", base.DEC)

----------------------------------------------------------------------------
-- Campos: paquete original embebido (Ethernet + IP + L4)
----------------------------------------------------------------------------
local f_orig_eth_dst  = ProtoField.ether("intreport.orig.eth_dst", "Paquete original - MAC destino")
local f_orig_eth_src  = ProtoField.ether("intreport.orig.eth_src", "Paquete original - MAC origen")
local f_orig_eth_type = ProtoField.uint16("intreport.orig.eth_type", "Paquete original - EtherType", base.HEX)
local f_orig_ip_src   = ProtoField.ipv4("intreport.orig.ip_src", "Paquete original - IP origen")
local f_orig_ip_dst   = ProtoField.ipv4("intreport.orig.ip_dst", "Paquete original - IP destino")
local f_orig_ip_proto = ProtoField.uint8("intreport.orig.ip_proto", "Paquete original - Protocolo", base.DEC)
local f_orig_ip_dscp  = ProtoField.uint8("intreport.orig.ip_dscp", "Paquete original - DSCP (0x20 = marcado INT)", base.HEX, nil, 0xFC)
local f_orig_l4_sport = ProtoField.uint16("intreport.orig.sport", "Paquete original - Puerto origen", base.DEC)
local f_orig_l4_dport = ProtoField.uint16("intreport.orig.dport", "Paquete original - Puerto destino", base.DEC)
local f_orig_icmp_type = ProtoField.uint8("intreport.orig.icmp_type", "Paquete original - ICMP type", base.DEC)
local f_orig_icmp_code = ProtoField.uint8("intreport.orig.icmp_code", "Paquete original - ICMP code", base.DEC)

----------------------------------------------------------------------------
-- Campos: int_shim (4 bytes) + int_header (8 bytes)
----------------------------------------------------------------------------
local f_shim_type = ProtoField.uint8("intreport.shim.type", "INT Shim - Type", base.DEC)
local f_shim_len  = ProtoField.uint8("intreport.shim.len", "INT Shim - Len (palabras de 4B, TOTAL del bloque INT)", base.DEC)

local f_hdr_ver          = ProtoField.uint8("intreport.hdr.ver", "INT Header - Version", base.DEC)
local f_hdr_hop_meta_len = ProtoField.uint8("intreport.hdr.hop_metadata_len", "INT Header - Hop metadata len (palabras, por hop)", base.DEC)
local f_hdr_remaining    = ProtoField.uint8("intreport.hdr.remaining_hop_cnt", "INT Header - Remaining hop cnt", base.DEC)
local f_hdr_ins_mask     = ProtoField.uint16("intreport.hdr.instruction_mask", "INT Header - Instruction Mask", base.HEX)
local f_hdr_seq          = ProtoField.uint16("intreport.hdr.seq", "INT Header - Seq (interno INT)", base.DEC)
local f_hdr_hop_count    = ProtoField.uint8("intreport.hdr.hop_count_calculado", "Switch count (CALCULADO: int_data_len / hop_metadata_len)", base.DEC)

----------------------------------------------------------------------------
-- Campos: metadata de cada hop (hasta 40 bytes cada uno, segun ins_map)
----------------------------------------------------------------------------
local f_hop_switch_id   = ProtoField.uint32("intreport.hop.switch_id", "switch_id", base.DEC)
local f_hop_ig_port     = ProtoField.uint16("intreport.hop.ingress_port", "ingress_port_id (L1)", base.DEC)
local f_hop_eg_port     = ProtoField.uint16("intreport.hop.egress_port", "egress_port_id (L1)", base.DEC)
local f_hop_latency     = ProtoField.uint32("intreport.hop.hop_latency", "hop_latency", base.DEC)
local f_hop_q_id        = ProtoField.uint8("intreport.hop.queue_id", "queue_occupancy_id", base.DEC)
local f_hop_q_occ       = ProtoField.uint24("intreport.hop.queue_occupancy", "queue_occupancy", base.DEC)
local f_hop_ig_ts       = ProtoField.uint64("intreport.hop.ingress_tstamp", "ingress_timestamp", base.DEC)
local f_hop_eg_ts       = ProtoField.uint64("intreport.hop.egress_tstamp", "egress_timestamp", base.DEC)
local f_hop_l2_ig       = ProtoField.uint16("intreport.hop.l2_ingress_port", "l2_ingress_port_id", base.DEC)
local f_hop_l2_eg       = ProtoField.uint16("intreport.hop.l2_egress_port", "l2_egress_port_id", base.DEC)
local f_hop_tx_util     = ProtoField.uint32("intreport.hop.egress_port_tx_util", "egress_port_tx_util", base.DEC)
local f_hop_pkt_len     = ProtoField.uint32("intreport.hop.pkt_len", "pkt_len (tamano del paquete, bytes)", base.DEC)

int_report_proto.fields = {
    f_rep_ver, f_rep_len, f_rep_nprot, f_rep_switch_id, f_rep_seq_num, f_rep_ingress_ts,
    f_orig_eth_dst, f_orig_eth_src, f_orig_eth_type, f_orig_ip_src, f_orig_ip_dst,
    f_orig_ip_proto, f_orig_ip_dscp, f_orig_l4_sport, f_orig_l4_dport,
    f_orig_icmp_type, f_orig_icmp_code,
    f_shim_type, f_shim_len,
    f_hdr_ver, f_hdr_hop_meta_len, f_hdr_remaining, f_hdr_ins_mask, f_hdr_seq, f_hdr_hop_count,
    f_hop_switch_id, f_hop_ig_port, f_hop_eg_port, f_hop_latency, f_hop_q_id, f_hop_q_occ,
    f_hop_ig_ts, f_hop_eg_ts, f_hop_l2_ig, f_hop_l2_eg, f_hop_tx_util, f_hop_pkt_len,
}

----------------------------------------------------------------------------
-- Operaciones a nivel de bit implementadas "a mano" (sin depender de
-- ninguna libreria bit/bit32, para que funcione en cualquier version de
-- Lua que traiga Wireshark).
----------------------------------------------------------------------------
local function band(a, b)
    local result, bitval = 0, 1
    while a > 0 and b > 0 do
        if (a % 2 == 1) and (b % 2 == 1) then
            result = result + bitval
        end
        bitval = bitval * 2
        a = math.floor(a / 2)
        b = math.floor(b / 2)
    end
    return result
end

local function rshift(a, n) return math.floor(a / (2 ^ n)) end
local function lshift(a, n) return a * (2 ^ n) end

----------------------------------------------------------------------------
-- Igual que la funcion Python: reordena los 16 bits del instruction_mask
-- (ver IntReport.__init__, lineas 294-297 de int_collector_influx.py)
----------------------------------------------------------------------------
local function fix_ins_map(raw16)
    local first_slice = lshift(band(raw16, 0x0F00), 4)
    local second_slice = rshift(band(raw16, 0xF000), 4)
    return rshift(first_slice + second_slice, 8)
end

----------------------------------------------------------------------------
-- Funcion principal del disector
----------------------------------------------------------------------------
function int_report_proto.dissector(buffer, pinfo, tree)
    local len = buffer:len()
    if len < 16 then return end

    pinfo.cols.protocol = "INT-REPORT"
    local subtree = tree:add(int_report_proto, buffer(), "INT Report (GEANT int-platforms)")

    ------------------------------------------------------------------
    -- 1) report_fixed_header (16 bytes)
    ------------------------------------------------------------------
    local hdr_tree = subtree:add(buffer(0, 16), "Report Fixed Header (16 bytes)")
    hdr_tree:add(f_rep_ver, buffer(0, 1))
    hdr_tree:add(f_rep_len, buffer(0, 1))
    hdr_tree:add(f_rep_nprot, buffer(1, 1))
    hdr_tree:add(f_rep_switch_id, buffer(4, 4))
    hdr_tree:add(f_rep_seq_num, buffer(8, 4))
    hdr_tree:add(f_rep_ingress_ts, buffer(12, 4))

    local report_switch_id = buffer(4, 4):uint()
    pinfo.cols.info = string.format("INT Report from switch %d", report_switch_id)

    ------------------------------------------------------------------
    -- 2) Paquete original embebido: Ethernet + IP + L4
    ------------------------------------------------------------------
    local off = 16
    local orig_tree = subtree:add(buffer(off, 14), "Paquete original embebido - Ethernet")
    orig_tree:add(f_orig_eth_dst, buffer(off, 6))
    orig_tree:add(f_orig_eth_src, buffer(off + 6, 6))
    orig_tree:add(f_orig_eth_type, buffer(off + 12, 2))
    off = off + 14

    local ip_tree = subtree:add(buffer(off, 20), "Paquete original embebido - IPv4")
    ip_tree:add(f_orig_ip_dscp, buffer(off + 1, 1))
    local ip_total_len = buffer(off + 2, 2):uint()
    ip_tree:add(buffer(off + 2, 2), string.format("Total Length: %d", ip_total_len))
    local proto = buffer(off + 9, 1):uint()
    ip_tree:add(f_orig_ip_proto, buffer(off + 9, 1))
    ip_tree:add(f_orig_ip_src, buffer(off + 12, 4))
    ip_tree:add(f_orig_ip_dst, buffer(off + 16, 4))
    off = off + 20

    -- offset del bloque INT: coincide con UDP_OFFSET/TCP_OFFSET/ICMP_OFFSET
    -- de int_collector_influx.py (14 Eth + 20 IP + cabecera L4)
    if proto == 17 then -- UDP
        local l4_tree = subtree:add(buffer(off, 8), "Paquete original embebido - UDP")
        l4_tree:add(f_orig_l4_sport, buffer(off, 2))
        l4_tree:add(f_orig_l4_dport, buffer(off + 2, 2))
        off = off + 8
    elseif proto == 6 then -- TCP
        local l4_tree = subtree:add(buffer(off, 20), "Paquete original embebido - TCP")
        l4_tree:add(f_orig_l4_sport, buffer(off, 2))
        l4_tree:add(f_orig_l4_dport, buffer(off + 2, 2))
        off = off + 20
    elseif proto == 1 then -- ICMP
        local l4_tree = subtree:add(buffer(off, 8), "Paquete original embebido - ICMP")
        l4_tree:add(f_orig_icmp_type, buffer(off, 1))
        l4_tree:add(f_orig_icmp_code, buffer(off + 1, 1))
        off = off + 8
    else
        subtree:add(buffer(off, 0), "Protocolo embebido no soportado: " .. proto)
        return
    end

    ------------------------------------------------------------------
    -- 3) int_shim (4 bytes)
    ------------------------------------------------------------------
    local shim_tree = subtree:add(buffer(off, 4), "INT Shim (4 bytes)")
    shim_tree:add(f_shim_type, buffer(off, 1))
    shim_tree:add(f_shim_len, buffer(off + 2, 1))
    local shim_len_words = buffer(off + 2, 1):uint()
    local int_data_len = shim_len_words - 3 -- igual que int_collector_influx.py linea 243
    off = off + 4

    ------------------------------------------------------------------
    -- 4) int_header (8 bytes)
    ------------------------------------------------------------------
    local ihdr_tree = subtree:add(buffer(off, 8), "INT Header (8 bytes)")
    ihdr_tree:add(f_hdr_ver, buffer(off, 1))
    ihdr_tree:add(f_hdr_hop_meta_len, buffer(off + 2, 1))
    local hop_metadata_len = band(buffer(off + 2, 1):uint(), 0x1F)
    ihdr_tree:add(f_hdr_remaining, buffer(off + 3, 1))
    local raw_mask = buffer(off + 4, 2):uint()
    local ins_map = fix_ins_map(raw_mask)
    ihdr_tree:add(f_hdr_ins_mask, buffer(off + 4, 2)):append_text(
        string.format("  (reordenado para lectura: 0x%02x)", ins_map))
    ihdr_tree:add(f_hdr_seq, buffer(off + 6, 2))
    off = off + 8

    local switch_count = 0
    if hop_metadata_len > 0 then
        switch_count = math.floor(int_data_len / hop_metadata_len)
    end
    ihdr_tree:add(f_hdr_hop_count, switch_count)
    pinfo.cols.info:append(string.format(", %d switch(es)", switch_count))

    ------------------------------------------------------------------
    -- 5) Metadata de cada hop, hop_count veces, segun bits de ins_map
    --    (misma logica que HopMetadata en int_collector_influx.py)
    ------------------------------------------------------------------
    for i = 1, switch_count do
        local hop_start = off
        local hop_tree = subtree:add(buffer(hop_start, 0), string.format("Hop metadata #%d", i - 1))
        local cur = off

        if band(ins_map, 0x80) ~= 0 then
            hop_tree:add(f_hop_switch_id, buffer(cur, 4)); cur = cur + 4
        end
        if band(ins_map, 0x40) ~= 0 then
            hop_tree:add(f_hop_ig_port, buffer(cur, 2)); cur = cur + 2
            hop_tree:add(f_hop_eg_port, buffer(cur, 2)); cur = cur + 2
        end
        if band(ins_map, 0x20) ~= 0 then
            hop_tree:add(f_hop_latency, buffer(cur, 4)); cur = cur + 4
        end
        if band(ins_map, 0x10) ~= 0 then
            hop_tree:add(f_hop_q_id, buffer(cur, 1)); cur = cur + 1
            hop_tree:add(f_hop_q_occ, buffer(cur, 3)); cur = cur + 3
        end
        if band(ins_map, 0x08) ~= 0 then
            hop_tree:add(f_hop_ig_ts, buffer(cur, 8)); cur = cur + 8
        end
        if band(ins_map, 0x04) ~= 0 then
            hop_tree:add(f_hop_eg_ts, buffer(cur, 8)); cur = cur + 8
        end
        if band(ins_map, 0x02) ~= 0 then
            hop_tree:add(f_hop_l2_ig, buffer(cur, 2)); cur = cur + 2
            hop_tree:add(f_hop_l2_eg, buffer(cur, 2)); cur = cur + 2
        end
        if band(ins_map, 0x01) ~= 0 then
            hop_tree:add(f_hop_tx_util, buffer(cur, 4)); cur = cur + 4
        end
        -- ANADIDO: tamano del paquete, siempre presente, sin bit de mascara
        hop_tree:add(f_hop_pkt_len, buffer(cur, 4)); cur = cur + 4

        hop_tree:set_len(cur - hop_start)
        off = cur
    end
end

----------------------------------------------------------------------------
-- Registrar el disector para el puerto UDP 6000 (el de tus commandsX.txt)
----------------------------------------------------------------------------
local udp_port_table = DissectorTable.get("udp.port")
udp_port_table:add(6000, int_report_proto)
