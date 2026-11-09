

#include "config.h"
#include <epan/packet.h>

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


    static int dissect_V2RUDP(tvbuff_t *packet_buffer, packet_info *packet_info, proto_tree *tree _U_, void *data _U_)
    {
        col_set_str(packet_info->cinfo, COL_PROTOCOL, protocol_short_name);
        /* Clear the info column */
        col_clear(packet_info->cinfo, COL_INFO);

        return tvb_captured_length(packet_buffer);
    }

    void proto_register_V2RUDP(void)
    {
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