# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.20)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_C_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project ("V2NetworkProtocol")
project ("V2WiresharkPlugin")
project ("TestsProject")

# Include sub-projects.
add_subdirectory ("V2NetworkProtocol")
add_subdirectory ("V2WiresharkPlugin")
add_subdirectory ("Tests")