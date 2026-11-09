# CMakeList.txt : CMake project for CMakeProject1, include source and define
# project specific logic here.
#
cmake_minimum_required(VERSION 3.20)
# Add source to this project's executable.
add_library (V2NetworkProtocol STATIC "src/message_parsing.cpp" "src/message_parsing.hpp")

target_include_directories(V2NetworkProtocol
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(V2NetworkProtocol PROPERTIES
        POSITION_INDEPENDENT_CODE ON
)

