#pragma once

enum class protocol_command_type : uint8_t {
    none=0,
    acknowledge=1,
    connect = 2,
    verify_connect=3,
    disconnect=4,
    ping=5,
    send_reliable=6,
    send_unreliable=7,
    send_fragment=8,
    bandwidth_limit=9,
    throttle_configure=10,
    send_unsequenced=11
};

enum class packet_type : uint16_t
{
    data = 0x0,
    connection_request = 0xffff,
};