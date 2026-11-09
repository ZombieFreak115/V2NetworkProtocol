# CMakeList.txt : CMake project for CMakeProject1, include source and define
# project specific logic here.
#
cmake_minimum_required(VERSION 3.20)

set(CMAKE_CXX_STANDARD 26)
# Add source to this project's executable.
add_executable(TestsProject "main.cpp")

target_link_libraries(TestsProject V2NetworkProtocol)


