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
#include "message_types.hpp"
#include "concepts.hpp"

#pragma comment(lib, "Ws2_32.lib")
#include <iostream>

#undef min


enum class parsing_state :uint8_t {
	parsing_packet_header = 0,
	parsing_segment_header = 1,
	parsing_segment_data = 2,
};
enum class message_parsing_error : uint8_t
{
	success = 0,
	not_enough_bytes_for_packet_header = 1,
	not_enough_bytes_for_segment_header = 2,
	not_enough_bytes_for_segment_data = 3,
};
enum class struct_parsing_error : uint8_t
{
	success = 0,
	not_enough_bytes_for_struct = 1,
};

template<concepts::network_struct struct_type>
struct_type parse_network_struct(std::span<const unsigned char> input_data, struct_parsing_error& err_out, uint64_t& buffer_bytes_read)
{
	struct_type out_buffer;
	if (input_data.size() < sizeof(struct_type))
	{
		err_out = struct_parsing_error::not_enough_bytes_for_struct;
		return out_buffer;
	}
	std::memcpy(&out_buffer, input_data.data(), sizeof(struct_type));
	out_buffer.to_host_order();
	buffer_bytes_read += sizeof(struct_type);
	err_out = struct_parsing_error::success;
	return out_buffer;
}

template<typename Visistor>
static struct_parsing_error visit_segment_required_fields(const data_segment& segment, uint64_t& buffer_bytes_read, Visistor&& on_segment_parsed)
{
	struct_parsing_error err = struct_parsing_error::success;
	switch (segment.segment_header.command_type)
	{
		case protocol_command_type::none:
		{
			// No required fields to parse
			on_segment_parsed(none_segment{});
			break;
		}
		case protocol_command_type::acknowledge:
		{
			auto segment_data = parse_network_struct<acknowledge_segment>(segment.variable_data, err, buffer_bytes_read);
			if (err == struct_parsing_error::success)
			{
				on_segment_parsed(segment_data);
			}
			break;
		}
		case protocol_command_type::connect:
		{
			auto segment_data = parse_network_struct<connect_segment>(segment.variable_data, err, buffer_bytes_read);
			if (err == struct_parsing_error::success)
			{
				on_segment_parsed(segment_data);
			}
			break;
		}
		case protocol_command_type::verify_connect:
		{
			auto segment_data = parse_network_struct<verify_connect_segment>(segment.variable_data, err, buffer_bytes_read);
			if (err == struct_parsing_error::success)
			{
				on_segment_parsed(segment_data);
			}
			break;
		}
		case protocol_command_type::disconnect:
		{
			auto segment_data = parse_network_struct<disconnect_segment>(segment.variable_data, err, buffer_bytes_read);
			if (err == struct_parsing_error::success)
			{
				on_segment_parsed(segment_data);
			}
			break;
		}
		case protocol_command_type::ping:
		{
			// No required fields to parse
			on_segment_parsed(ping_segment{});
			break;
		}
		case protocol_command_type::send_reliable:
		{
			// No required fields to parse
			on_segment_parsed(send_reliable_segment{});
			break;
		}
		case protocol_command_type::send_unreliable:
		{
			auto segment_data = parse_network_struct<send_unreliable_segment>(segment.variable_data, err, buffer_bytes_read);
			if (err == struct_parsing_error::success)
			{
				on_segment_parsed(segment_data);
			}
			break;
		}
		case protocol_command_type::send_fragment:
		{
			auto segment_data = parse_network_struct<send_fragment_segment>(segment.variable_data, err, buffer_bytes_read);
			if (err == struct_parsing_error::success)
			{
				on_segment_parsed(segment_data);
			}
			break;
		}
		case protocol_command_type::bandwidth_limit:
		{
			auto segment_data = parse_network_struct<bandwidth_limit_segment>(segment.variable_data, err, buffer_bytes_read);
			if (err == struct_parsing_error::success)
			{
				on_segment_parsed(segment_data);
			}
			break;
		}
		case protocol_command_type::throttle_configure:
		{
			auto segment_data = parse_network_struct<throttle_configure_segment>(segment.variable_data, err, buffer_bytes_read);
			if (err == struct_parsing_error::success)
			{
				on_segment_parsed(segment_data);
			}
			break;
		}
		case protocol_command_type::send_unsequenced:
		{
			auto segment_data = parse_network_struct<send_unsequenced_segment>(segment.variable_data, err, buffer_bytes_read);
			if (err == struct_parsing_error::success)
			{
				on_segment_parsed(segment_data);
			}
			break;
		}
		default:
		{
			break;
		}
	}
	return err;
}




network_message parse_network_message_stateless(std::span<const unsigned char> input_data, message_parsing_error& err_out, uint64_t& buffer_bytes_read);

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
					out_buffer = network_message{};
				}
			}
		}
		else {
			auto& current_data_segment = out_buffer.data_segments[current_segment_index];
			if (parse_state == parsing_state::parsing_segment_header) {
				unsigned char* binary_segment_header = reinterpret_cast<unsigned char*>(&current_data_segment.segment_header);
				uint64_t bytes_to_read = sizeof(data_segment_header) - segment_bytes_read;
				bytes_to_read = std::min(bytes_to_read, buffer_size - buffer_bytes_read);
				std::memcpy(binary_segment_header + segment_bytes_read, input_data.data() + buffer_bytes_read, bytes_to_read);
				segment_bytes_read += bytes_to_read;
				buffer_bytes_read += bytes_to_read;
				if (segment_bytes_read == sizeof(data_segment_header)) {
					current_data_segment.segment_header.to_host_order();
					segment_bytes_read = 0; // reset as segment header is done
					parse_state = parsing_state::parsing_segment_data;
					current_segment_size = current_data_segment.segment_header.data_size - sizeof(data_segment_header); // Size includes the header itself, subtract that
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
						out_buffer = network_message{}; // Destroy it
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
