
#include <fstream>
#include <iostream>
#include <vector>
#include <array>
#include "../V2NetworkProtocol/src/message_parsing.hpp"

int main()
{
	std::string filename{"V2JoinPackets.bin"};
	std::ifstream fs{filename, fs.binary };

    if (!fs.is_open())
        std::cout << "failed to open " << filename << '\n';
    else
    {
        std::array<unsigned char, 10*1024> read_buffer{};
        uint32_t bytes_read = 0;
        while (fs.peek() != EOF) {
            fs.read(reinterpret_cast<char*>(read_buffer.data()), read_buffer.size());
            bytes_read = fs.gcount();
            parse_network_message(std::span<unsigned char>(read_buffer.data(), bytes_read), [&](network_message& msg) {
                msg.print();
            });
        }
    }
	return 0;
}
