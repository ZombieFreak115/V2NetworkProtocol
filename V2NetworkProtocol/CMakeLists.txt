# CMakeList.txt : CMake project for CMakeProject1, include source and define
# project specific logic here.
#

# Add source to this project's executable.
add_executable (V2NetworkProtocol "main.cpp" "message_parsing.cpp" "message_parsing.hpp")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET V2NetworkProtocol PROPERTY CXX_STANDARD 26)
endif()

# TODO: Add tests and install targets if needed.
