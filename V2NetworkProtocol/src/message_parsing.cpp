#include "message_parsing.hpp"


network_message parse_network_message_stateless(std::span<const unsigned char> input_data, parsing_error& err_out, uint64_t& buffer_bytes_read) {
	uint64_t buffer_size = input_data.size();
	parsing_state parse_state = parsing_state::parsing_packet_header;
	uint16_t segments_to_parse = 0;
	uint16_t current_segment_index = 0;
	uint32_t current_segment_size = 0;
	network_message out_buffer{};

	buffer_bytes_read = 0;
	while (buffer_bytes_read != buffer_size) {

		switch (parse_state)
		{
			// We dont need to worry about buffer_bytes_read here, since the packet header will ALWAYS be parsed first
			case parsing_state::parsing_packet_header:
			{
				unsigned char* binary_header = reinterpret_cast<unsigned char*>(&out_buffer.header);
				uint64_t header_size = sizeof(out_buffer.header);
				if (buffer_size < header_size)
				{
					err_out = parsing_error::not_enough_bytes_for_packet_header;
					return out_buffer;
				}
				std::memcpy(binary_header, input_data.data(), header_size);
				buffer_bytes_read += header_size;
				out_buffer.header.to_host_order();
				// If there are segments to parse, reset variables and start parsing it
				segments_to_parse = out_buffer.header.data_segment_count;
				if(segments_to_parse > 0) {
					parse_state = parsing_state::parsing_segment_header;
					out_buffer.data_segments.resize(segments_to_parse);
					current_segment_index = 0;
				}
				else {
					// If there are no data segments, then we are done
					err_out = parsing_error::success;
					return out_buffer;
				}
			}
		case parsing_state::parsing_segment_header:
		{
			if (current_segment_index >= segments_to_parse)
			{
				err_out = parsing_error::not_enough_bytes_for_segment_header;
				return out_buffer;
			}
			auto& current_data_segment = out_buffer.data_segments[current_segment_index];
			unsigned char* binary_segment_header = reinterpret_cast<unsigned char*>(&current_data_segment.segment_header);
			uint64_t segment_header_size = sizeof(current_data_segment.segment_header);
			if (buffer_size - buffer_bytes_read < segment_header_size)
			{
				err_out = parsing_error::not_enough_bytes_for_segment_header;
				return out_buffer;
			}
			std::memcpy(binary_segment_header, input_data.data() + buffer_bytes_read, segment_header_size);
			buffer_bytes_read += segment_header_size;

			current_data_segment.segment_header.to_host_order();
			parse_state = parsing_state::parsing_segment_data;
			current_segment_size = current_data_segment.segment_header.data_size - sizeof(current_data_segment.segment_header); // Size includes the header itself, subtract that
			current_data_segment.variable_data.resize(current_segment_size);
		}
		case parsing_state::parsing_segment_data:
		{
			if (current_segment_index >= segments_to_parse)
			{
				err_out = parsing_error::not_enough_bytes_for_segment_data;
				return out_buffer;
			}
			auto& current_data_segment = out_buffer.data_segments[current_segment_index];
			if (buffer_size - buffer_bytes_read < current_segment_size)
			{
				err_out = parsing_error::not_enough_bytes_for_segment_data;
				return out_buffer;
			}
			std::memcpy(current_data_segment.variable_data.data(), input_data.data() + buffer_bytes_read, current_segment_size);
			buffer_bytes_read += current_segment_size;

			current_segment_index++;
			current_segment_size = 0;
			if (current_segment_index == segments_to_parse) {
				// We are done with this message
				err_out = parsing_error::success;
				return out_buffer;
			}
			// Begin to parse the next segment header as there are still segments left to parse
			parse_state = parsing_state::parsing_segment_header;
		}
		}
	}

}