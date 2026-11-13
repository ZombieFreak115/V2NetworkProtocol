#pragma once
#include "message_enums.hpp"

struct connect_segment
{
    uint16_t outgoing_peer_id;
    uint16_t mtu;
    uint32_t window_size;
    uint32_t channel_count;
    uint32_t incoming_bandwidth;
    uint32_t outgoing_bandwidth;
    uint32_t packet_throttle_interval;
    uint32_t packet_throttle_acceleration;
    uint32_t packet_throttle_deceleration;
    void to_host_order() {
        outgoing_peer_id = ntohs(outgoing_peer_id);
        mtu = ntohs(mtu);
        window_size = ntohl(window_size);
        channel_count = ntohl(channel_count);
        incoming_bandwidth = ntohl(incoming_bandwidth);
        outgoing_bandwidth = ntohl(outgoing_bandwidth);
        packet_throttle_interval = ntohl(packet_throttle_interval);
        packet_throttle_acceleration = ntohl(packet_throttle_acceleration);
        packet_throttle_deceleration = ntohl(packet_throttle_deceleration);
    }
};
static_assert(sizeof(connect_segment) == 32);

struct verify_connect_segment : connect_segment
{
    // They share the same fields
};
static_assert(sizeof(verify_connect_segment) == 32);

struct send_reliable_segment
{
    // No required fields
};
static_assert(sizeof(send_reliable_segment) == 1);

struct ping_segment
{
    // No required fields
};
static_assert(sizeof(ping_segment) == 1);

struct none_segment
{
    // No required fields
};
static_assert(sizeof(none_segment) == 1);

struct bandwidth_limit_segment {
    uint32_t incoming_bandwidth;
    uint32_t outgoing_bandwidth;
    void to_host_order() {
        incoming_bandwidth = ntohl(incoming_bandwidth);
        outgoing_bandwidth = ntohl(outgoing_bandwidth);
    }
};
static_assert(sizeof(bandwidth_limit_segment) == 8);

struct acknowledge_segment {
    uint32_t received_reliable_seq_num;
    uint32_t received_sent_time;
    void to_host_order() {
        received_reliable_seq_num = ntohl(received_reliable_seq_num);
        received_sent_time = ntohl(received_sent_time);
    }
};
static_assert(sizeof(acknowledge_segment) == 8);

struct disconnect_segment {
    uint32_t data;
    void to_host_order() {
        data = ntohl(data);
    }
};
static_assert(sizeof(disconnect_segment) == 4);

struct send_unreliable_segment {
    uint32_t unreliable_seq_num;
    void to_host_order() {
        unreliable_seq_num = ntohl(unreliable_seq_num);
    }
};
static_assert(sizeof(send_unreliable_segment) == 4);

struct send_fragment_segment {
    uint32_t start_seq_num;
    uint32_t fragment_count;
    uint32_t fragment_number;
    uint32_t total_length;
    uint32_t fragment_offset;
    void to_host_order() {
        start_seq_num = ntohl(start_seq_num);
        fragment_count = ntohl(fragment_count);
        fragment_number = ntohl(fragment_number);
        total_length = ntohl(total_length);
        fragment_offset = ntohl(fragment_offset);
    }
};
static_assert(sizeof(send_fragment_segment) == 20);

struct send_unsequenced_segment {
    uint32_t unsequenced_group;
    void to_host_order() {
        unsequenced_group = ntohl(unsequenced_group);
    }
};
static_assert(sizeof(send_unsequenced_segment) == 4);

struct throttle_configure_segment {
    uint32_t packet_throttle_interval;
    uint32_t packet_throttle_acceleration;
    uint32_t packet_throttle_deceleration;
    void to_host_order() {
        packet_throttle_interval = ntohl(packet_throttle_interval);
        packet_throttle_acceleration = ntohl(packet_throttle_acceleration);
        packet_throttle_deceleration = ntohl(packet_throttle_deceleration);
    }
};
static_assert(sizeof(throttle_configure_segment) == 12);


struct data_segment_header {
    protocol_command_type command_type;
    uint8_t channel_id;
    uint8_t flags;
    uint8_t reserved;
    uint32_t data_size;
    uint32_t reliable_seq_num;

    void to_host_order() {
        data_size = ntohl(data_size);
        reliable_seq_num = ntohl(reliable_seq_num);
    }


};
static_assert(sizeof(data_segment_header) == 12);

struct data_segment {
    data_segment_header segment_header;
    std::vector<unsigned char> variable_data;

};




struct message_header {
    // header
    packet_type type;
    uint16_t data_segment_count;
    uint32_t sequence_num;
    uint32_t session_handle;

    void to_host_order() {
        //type = ntohs(type); // don't need to convert the type var
        data_segment_count = ntohs(data_segment_count);
        sequence_num = ntohl(sequence_num);
        session_handle = ntohl(session_handle);
    }

};
static_assert(sizeof(message_header) == 12);

struct network_message {
    message_header header;
    std::vector<data_segment> data_segments;

    void print() const {

    }

};