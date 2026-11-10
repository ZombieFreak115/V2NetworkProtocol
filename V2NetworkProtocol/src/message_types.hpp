#pragma once
#include "message_enums.hpp"

// Verify connect segment uses the same thing
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

    }
};
struct bandwitdh_limit_segment {
    uint32_t incoming_bandwidth;
    uint32_t outgoing_bandwidth;
    void to_host_order() {

    }
};
struct acknowledge_segment {
    uint32_t receivedReliableSequenceNumber;
    uint32_t receivedSentTime;
    void to_host_order() {

    }
};
struct disconnect_segment {
    uint32_t data;
    void to_host_order() {

    }
};

struct send_unreliable_segment {
    uint32_t unreliableSequenceNumber;
    void to_host_order() {

    }
};

struct send_fragment_segment {
    uint32_t startSequenceNumber;
    uint32_t fragmentCount;
    uint32_t fragmentNumber;
    uint32_t totalLength;
    uint32_t fragmentOffset;
    void to_host_order() {

    }
};

struct send_unsequenced_segment {
    uint32_t unsequencedGroup;
    void to_host_order() {

    }
};

struct throttle_configure_segment {
    uint32_t packetThrottleInterval;
    uint32_t packetThrottleAcceleration;
    uint32_t packetThrottleDeceleration;
    void to_host_order() {

    }
};


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