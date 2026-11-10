#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <span>
#ifdef _WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif
#include <algorithm>
#include <string>

#pragma comment(lib, "Ws2_32.lib")
#include <iostream>

#undef min

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


struct variable_data_segment_header {
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
static_assert(sizeof(variable_data_segment_header) == 12);

struct variable_data_segment {
	variable_data_segment_header segment_header;
	std::vector<unsigned char> variable_data;

};

enum class packet_type : uint16_t
{
	data = 0x0,
	connection_request = 0xffff,
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
	std::vector<variable_data_segment> data_segments;

	void print() const {

	}

};

enum class parsing_state :uint8_t {
	parsing_packet_header = 0,
	parsing_segment_header = 1,
	parsing_segment_data = 2,
};
enum class parsing_error : uint8_t
{
	success = 0,
	not_enough_bytes_for_packet_header = 1,
	not_enough_bytes_for_segment_header = 2,
	not_enough_bytes_for_segment_data = 3,
};

network_message parse_network_message_stateless(std::span<const unsigned char> input_data, parsing_error& err_out, uint64_t& buffer_bytes_read);

template<typename F>
void parse_network_message_statefull(std::span<unsigned char> input_data, F&& on_message_parsed) {
	uint64_t buffer_size = input_data.size();
	static parsing_state parse_state = parsing_state::parsing_packet_header;
	static uint64_t segment_bytes_read = 0; // main header also counts as a segment
	static uint16_t segments_to_parse = 0;
	static uint16_t current_segment_index = 0;
	static uint32_t current_segment_size = 0;
	static network_message out_buffer{};

	uint64_t buffer_bytes_read = 0;
	while (buffer_bytes_read != buffer_size) {
		if (parse_state == parsing_state::parsing_packet_header) {
			unsigned char* binary_header = reinterpret_cast<unsigned char*>(&out_buffer.header);
			uint64_t bytes_to_read = sizeof(message_header) - segment_bytes_read;
			bytes_to_read = std::min<uint64_t>(bytes_to_read, buffer_size - buffer_bytes_read);
			std::memcpy(binary_header + segment_bytes_read, input_data.data() + buffer_bytes_read, bytes_to_read);
			segment_bytes_read += bytes_to_read;
			buffer_bytes_read += bytes_to_read;
			if (segment_bytes_read == sizeof(message_header)) {
				out_buffer.header.to_host_order();
				segment_bytes_read = 0; // reset as main header is done
				// If there are no data segments, then we are done
				if(out_buffer.header.data_segment_count > 0) {
					parse_state = parsing_state::parsing_segment_header;
					segments_to_parse = out_buffer.header.data_segment_count;
					out_buffer.data_segments.resize(segments_to_parse);
					current_segment_index = 0;
				}
				else {
					on_message_parsed(out_buffer);
					out_buffer = {};
				}
			}
		}
		else {
			auto& current_data_segment = out_buffer.data_segments[current_segment_index];
			if (parse_state == parsing_state::parsing_segment_header) {
				unsigned char* binary_segment_header = reinterpret_cast<unsigned char*>(&current_data_segment.segment_header);
				uint64_t bytes_to_read = sizeof(variable_data_segment_header) - segment_bytes_read;
				bytes_to_read = std::min(bytes_to_read, buffer_size - buffer_bytes_read);
				std::memcpy(binary_segment_header + segment_bytes_read, input_data.data() + buffer_bytes_read, bytes_to_read);
				segment_bytes_read += bytes_to_read;
				buffer_bytes_read += bytes_to_read;
				if (segment_bytes_read == sizeof(variable_data_segment_header)) {
					current_data_segment.segment_header.to_host_order();
					segment_bytes_read = 0; // reset as segment header is done
					parse_state = parsing_state::parsing_segment_data;
					current_segment_size = current_data_segment.segment_header.data_size - sizeof(variable_data_segment_header); // Size includes the header itself, subtract that
					current_data_segment.variable_data.resize(current_segment_size);

				}

			}
			else { // parsing_segment_data
				uint64_t bytes_to_read = current_segment_size - segment_bytes_read;
				bytes_to_read = std::min(bytes_to_read, buffer_size - buffer_bytes_read);
				std::memcpy(current_data_segment.variable_data.data() + segment_bytes_read, input_data.data() + buffer_bytes_read, bytes_to_read);
				segment_bytes_read += bytes_to_read;
				buffer_bytes_read += bytes_to_read;
				if (segment_bytes_read == current_segment_size) {
					current_segment_index++;
					segment_bytes_read = 0;
					current_segment_size = 0;
					if (current_segment_index == segments_to_parse) {
						// We are done with this message, reset all message-related state and run the provided functor
						on_message_parsed(out_buffer);
						out_buffer = {}; // Destroy it
						parse_state = parsing_state::parsing_packet_header;
						segments_to_parse = 0;
						current_segment_index = 0;
					}
					else {
						// Begin to parse the next segment header as there are still segments left to parse
						parse_state = parsing_state::parsing_segment_header;
					}
				}
			}
			
		}
	}
	


}
