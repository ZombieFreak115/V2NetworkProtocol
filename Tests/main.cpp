
#include <fstream>
#include <iostream>
#include <vector>
#include <array>
#include "message_parsing.hpp"

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
            parse_network_message_statefull(std::span<unsigned char>(read_buffer.data(), bytes_read), [&](network_message& msg) {
                msg.print();
            });
        }
        fs.clear();
        fs.seekg(0, std::ios::beg);
        std::vector<unsigned char> buffer(bytes_read);
        fs.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        parsing_error err;
        uint64_t processed;
        network_message msg = parse_network_message_stateless(buffer, err, processed );
        int i = 5;
    }
	return 0;
}
