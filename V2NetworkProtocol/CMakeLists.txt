# CMakeList.txt : CMake project for CMakeProject1, include source and define
# project specific logic here.
#
cmake_minimum_required(VERSION 3.20)
# Add source to this project's executable.
add_executable (V2NetworkProtocol "main.cpp" "message_parsing.cpp" "message_parsing.hpp")

set_target_properties(V2NetworkProtocol PROPERTIES
        POSITION_INDEPENDENT_CODE ON
)

# TODO: Add tests and install targets if needed.
