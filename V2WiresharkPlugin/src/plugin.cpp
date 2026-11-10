

#include "config.h"
#include <epan/packet.h>
#include "message_parsing.hpp"

constexpr uint16_t v2_udp_ports[] = {1630, 1631, 1632, 1633, 1634, 1635, 1636, 1637, 1638, 1639, 1640, 1641};
constexpr uint32_t udp_port_arr_size = sizeof(v2_udp_ports)/sizeof(v2_udp_ports[0]);

static const char* protocol_short_name = "V2-RUDP";
static const char* protocol_filter_name = "v2-rudp";
static const char* protocol_name = "Vic2-Reliable-UDP";

static const char* dissector_name = "Vic2-Reliable-UDP-dissector";

static int protocol_handle;

static dissector_handle_t dissector_handle;


extern "C" {
    extern WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;

    extern WS_DLL_PUBLIC_DEF const int plugin_want_major =
        WIRESHARK_VERSION_MAJOR;

    extern WS_DLL_PUBLIC_DEF const int plugin_want_minor =
        WIRESHARK_VERSION_MINOR;

    WS_DLL_PUBLIC void plugin_register(void);

    static int packet_header_unk1;
    static int packet_header_data_segment_count;;
    static int packet_header_sequence_num;
    static int packet_header_unk3;
    static int tree_main = -1;


    static int dissect_V2RUDP(tvbuff_t *packet_buffer, packet_info *packet_info, proto_tree *tree, void *data _U_)
    {
        col_set_str(packet_info->cinfo, COL_PROTOCOL, protocol_short_name);
        /* Clear the info column */
        col_clear(packet_info->cinfo, COL_INFO);
        const guint length = tvb_reported_length(packet_buffer);
        const guint8* packet_data = tvb_get_ptr(packet_buffer,0, length);
        parsing_error err;
        uint64_t consumed_bytes;
        network_message msg = parse_network_message_stateless(std::span(packet_data, length),err,  consumed_bytes);
        if (err == parsing_error::not_enough_bytes_for_packet_header)
        {
            return 0;
        }
        proto_item *ti = proto_tree_add_item(tree, protocol_handle, packet_buffer, 0 , -1, ENC_NA);
        proto_tree *proto_tree = proto_item_add_subtree(ti, tree_main);
        uint64_t index = 0;
        
        proto_tree_add_uint(proto_tree, packet_header_unk1, packet_buffer, index, sizeof(message_header::unk_1), msg.header.unk_1);
        index += sizeof(message_header::unk_1);
        proto_tree_add_uint(proto_tree, packet_header_data_segment_count, packet_buffer, index, sizeof(message_header::data_segment_count), msg.header.data_segment_count);
        index += sizeof(message_header::data_segment_count);
        proto_tree_add_uint(proto_tree, packet_header_sequence_num, packet_buffer, index, sizeof(message_header::sequence_num), msg.header.sequence_num);
        index += sizeof(message_header::sequence_num);

        proto_tree_add_uint(proto_tree, packet_header_unk3, packet_buffer, index, sizeof(message_header::unk_3), msg.header.unk_3);
        index += sizeof(message_header::unk_3);
        for (const auto& segment : msg.data_segments)
        {

        }

        return index;
    }

    void proto_register_V2RUDP(void)
    {
        static hf_register_info header_fields[] = {
            { &packet_header_unk1, { "unk1", "V2RUDP.unk1", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
            { &packet_header_data_segment_count, { "Segment count", "V2RUDP.segment_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
            { &packet_header_sequence_num, { "Sequence number", "V2RUDP.sequence_num", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
            { &packet_header_unk3, { "unk3", "V2RUDP.unk3", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }}
        };
        /* Setup protocol subtree array */
        static int *subtree_arrays[] = {
            &tree_main
        };


        protocol_handle = proto_register_protocol (
            protocol_name, /* protocol name        */
            protocol_short_name,          /* protocol short name  */
            protocol_filter_name           /* protocol filter_name */
            );

        dissector_handle = register_dissector_with_description (
            dissector_name,          /* dissector name           */
            "Parses reliable UDP messages sent by Victoria 2 between server and client", /* dissector description    */
            dissect_V2RUDP,    /* dissector function       */
            protocol_handle       /* protocol being dissected */
            );

        proto_register_field_array(protocol_handle, header_fields, array_length(header_fields));
        proto_register_subtree_array(subtree_arrays, array_length(subtree_arrays));
    }

    void proto_reg_handoff_V2RUDP(void)
    {
        for(uint32_t i = 0; i < udp_port_arr_size; i++)
        {
            dissector_add_uint("udp.port", v2_udp_ports[i], dissector_handle);
        }
    }
    void plugin_register(void)
    {
        static proto_plugin plugin_v2rudp;
        plugin_v2rudp.register_protoinfo = proto_register_V2RUDP;
        plugin_v2rudp.register_handoff = proto_reg_handoff_V2RUDP;
        proto_register_plugin(&plugin_v2rudp);
    }

}