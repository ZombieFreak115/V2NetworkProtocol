

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

    static int packet_header_type;
    static int packet_header_data_segment_count;;
    static int packet_header_sequence_num;
    static int packet_header_session_handle;

    static int segment_header_command_type;
    static int segment_header_channel_id;
    static int segment_header_flags;
    static int segment_header_reserved;;
    static int segment_header_data_size;
    static int segment_header_reliable_seq_num;

    static int segment_payload_data;

    static int main_array = -1;
    static int header_array = -1;
    static int segment_array = -1;
    static int segment_header_array = -1;
    static int segment_payload_array = -1;


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
        proto_item* ti_main = nullptr;
        proto_item* ti_header = nullptr;
        auto* proto_tree = proto_tree_add_subtree(tree, packet_buffer, 0, -1, main_array, &ti_main, "V2-RUDP");
        auto* header_tree = proto_tree_add_subtree(proto_tree, packet_buffer, 0, sizeof(message_header), header_array, &ti_header, "V2 Packet Header");

        uint64_t index = 0;

        proto_tree_add_uint(header_tree, packet_header_type, packet_buffer, index, sizeof(message_header::type), uint16_t(msg.header.type));
        index += sizeof(message_header::type);
        proto_tree_add_uint(header_tree, packet_header_data_segment_count, packet_buffer, index, sizeof(message_header::data_segment_count), msg.header.data_segment_count);
        index += sizeof(message_header::data_segment_count);
        proto_tree_add_uint(header_tree, packet_header_sequence_num, packet_buffer, index, sizeof(message_header::sequence_num), msg.header.sequence_num);
        index += sizeof(message_header::sequence_num);

        proto_tree_add_uint(header_tree, packet_header_session_handle, packet_buffer, index, sizeof(message_header::session_handle), msg.header.session_handle);
        index += sizeof(message_header::session_handle);
        for (const auto& segment : msg.data_segments)
        {
            proto_item* ti_segment = nullptr;
            proto_item* ti_segment_header = nullptr;
            proto_item* ti_segment_payload = nullptr;
            auto* segment_tree = proto_tree_add_subtree(proto_tree, packet_buffer, index, sizeof(segment.segment_header) + segment.variable_data.size() , segment_array, &ti_segment , "V2 Data Segment");
            auto* segment_header_tree = proto_tree_add_subtree(segment_tree, packet_buffer, index, sizeof(segment.segment_header) , segment_header_array, &ti_segment_header , "V2 Data Segment Header");

            proto_tree_add_uint(segment_header_tree, segment_header_command_type, packet_buffer, index, sizeof(segment.segment_header.command_type), uint8_t(segment.segment_header.command_type));
            index += sizeof(segment.segment_header.command_type);
            proto_tree_add_uint(segment_header_tree, segment_header_channel_id, packet_buffer, index, sizeof(segment.segment_header.channel_id), segment.segment_header.channel_id);
            index += sizeof(segment.segment_header.channel_id);
            proto_tree_add_uint(segment_header_tree, segment_header_flags, packet_buffer, index, sizeof(segment.segment_header.flags), segment.segment_header.flags);
            index += sizeof(segment.segment_header.flags);
            proto_tree_add_uint(segment_header_tree, segment_header_reserved, packet_buffer, index, sizeof(segment.segment_header.reserved), segment.segment_header.reserved);
            index += sizeof(segment.segment_header.reserved);

            proto_tree_add_uint(segment_header_tree, segment_header_data_size, packet_buffer, index, sizeof(segment.segment_header.data_size), segment.segment_header.data_size);
            index += sizeof(segment.segment_header.data_size);

            proto_tree_add_uint(segment_header_tree, segment_header_reliable_seq_num, packet_buffer, index, sizeof(segment.segment_header.reliable_seq_num), segment.segment_header.reliable_seq_num);
            index += sizeof(segment.segment_header.reliable_seq_num);

            auto* segment_payload_tree = proto_tree_add_subtree(segment_tree, packet_buffer, index, segment.variable_data.size() , segment_payload_array, &ti_segment_payload , "V2 Data Segment Payload");
            proto_tree_add_bytes(segment_payload_tree, segment_payload_data, packet_buffer,  index, segment.variable_data.size() , segment.variable_data.data());
            index += segment.variable_data.size();
        }

        return index;
    }

    void proto_register_V2RUDP(void)
    {
        static const value_string packet_type_names[] = {
            { uint16_t(packet_type::data), "Data" },
            { uint16_t(packet_type::connection_request), "Connection Request" }
        };
        static const value_string protocol_command_type_names[] = {
            { uint8_t(protocol_command_type::none), "None" },
            { uint8_t(protocol_command_type::acknowledge), "Acknowledge" },
            { uint8_t(protocol_command_type::connect), "Connect" },
            { uint8_t(protocol_command_type::verify_connect), "Verify connect" },
            { uint8_t(protocol_command_type::disconnect), "Disconnect" },
            { uint8_t(protocol_command_type::ping), "Ping" },
            { uint8_t(protocol_command_type::send_reliable), "Send reliable" },
            { uint8_t(protocol_command_type::send_unreliable), "Send unreliable" },
            { uint8_t(protocol_command_type::send_fragment), "Send fragment" },
            { uint8_t(protocol_command_type::bandwidth_limit), "Bandwidth limit" },
            { uint8_t(protocol_command_type::throttle_configure), "Throttle configure" },
            { uint8_t(protocol_command_type::send_unsequenced), "Send unsequenced" }
        };

        static hf_register_info header_fields[] = {
            { &packet_header_type, { "Type", "V2RUDP.type", FT_UINT16, BASE_HEX, VALS(packet_type_names), 0x0, NULL, HFILL }},
            { &packet_header_data_segment_count, { "Segment count", "V2RUDP.segment_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
            { &packet_header_sequence_num, { "Sequence number", "V2RUDP.sequence_num", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
            { &packet_header_session_handle, { "Session handle", "V2RUDP.session_handle", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }}
        };
        static hf_register_info segment_header_fields[] = {
            { &segment_header_command_type, { "Segment command", "V2RUDP.segment_command", FT_UINT8, BASE_HEX, VALS(protocol_command_type_names), 0x0, NULL, HFILL }},
            { &segment_header_channel_id, { "Channel ID", "V2RUDP.channel_id", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
            { &segment_header_flags, { "Flags", "V2RUDP.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
            { &segment_header_reserved, { "Reserved", "V2RUDP.reserved", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
            { &segment_header_data_size, { "Data size", "V2RUDP.data_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
            { &segment_header_reliable_seq_num, { "Reliable sequence number", "V2RUDP.reliable_sequence_number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        };
        static hf_register_info segment_payload_fields[] = {
            { &segment_payload_data, { "Payload", "V2RUDP.segment_payload", FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }},
        };
        /* Setup protocol subtree array */
        static int *subtree_arrays[] = {
            &main_array,
            &header_array,
            &segment_array,
            &segment_header_array,
            &segment_payload_array
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
        proto_register_field_array(protocol_handle, segment_header_fields, array_length(segment_header_fields));
        proto_register_field_array(protocol_handle, segment_payload_fields, array_length(segment_payload_fields));
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