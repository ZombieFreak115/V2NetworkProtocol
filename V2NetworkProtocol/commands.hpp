#pragma once

#include "message_parsing.hpp"

// Exists in the variable_data payload. May be absent in some commands 
struct command_header {
	uint32_t counter;
	uint16_t command_type;
	uint16_t unk_1;
};


struct MoveUnitCommand {
	command_header header;
	uint32_t unk_1[23];
	uint8_t[3];


	static constexpr uint64_t min_size = 0x6f;
	static constexpr uint64_t max_size = 0x6f;
};