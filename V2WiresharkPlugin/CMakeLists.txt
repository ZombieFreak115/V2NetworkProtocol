# CMakeList.txt : CMake project for CMakeProject1, include source and define
# project specific logic here.
#
cmake_minimum_required(VERSION 3.20)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_C_STANDARD 23)

find_package(Wireshark CONFIG REQUIRED)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}"
            CACHE PATH "Installation prefix" FORCE
    )
endif()

if(NOT Wireshark_PLUGINS_ENABLED)
    message(WARNING "Wireshark was compiled without support for plugins")
endif()

# External plugins must define HAVE_SSIZE_T for the plugin toolchain.
include(CheckTypeSize)
check_type_size("ssize_t" SSIZE_T)


set(CMAKE_C_VISIBILITY_PRESET hidden)
if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

add_compile_definitions(
        VERSION=\"${PROJECT_VERSION}\"
        $<$<BOOL:${HAVE_SSIZE_T}>:HAVE_SSIZE_T>
)

add_library(V2WiresharkPlugin MODULE "src/plugin.cpp")

set_target_properties(V2WiresharkPlugin PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(V2WiresharkPlugin epan)
target_link_libraries(V2WiresharkPlugin V2NetworkProtocol)

# This is the normal installation target to CMAKE_INSTALL_PREFIX. It is relocatable
# using DESTDIR or cmake --install. By default CMAKE_INSTALL_PREFIX should be configured
# correctly for Wireshark's system installation prefix.
install(TARGETS V2WiresharkPlugin
        LIBRARY DESTINATION "${Wireshark_PLUGIN_LIBDIR}/epan" NAMELINK_SKIP
)

# This custom target installs the plugin to the plugin dir in WiresharkConfig.cmake.
# It does not use CMAKE_INSTALL_PREFIX.
add_custom_target(InstallPlugin
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:V2WiresharkPlugin> "${Wireshark_PLUGIN_INSTALL_DIR}/epan"
        COMMENT "Installing plugin to: ${Wireshark_PLUGIN_INSTALL_DIR}/epan"
)

string(TOLOWER "${PROJECT_NAME}-${PROJECT_VERSION}" _pkgname)

add_custom_target(package_prep
        COMMAND ${CMAKE_COMMAND} -E make_directory  ${CMAKE_BINARY_DIR}/${_pkgname}
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/README $<TARGET_FILE:V2WiresharkPlugin> ${CMAKE_BINARY_DIR}/${_pkgname}
)

add_custom_target(package
        COMMAND ${CMAKE_COMMAND} -E tar czf ${CMAKE_BINARY_DIR}/${_pkgname}.tar.gz --format=gnutar -- ${CMAKE_BINARY_DIR}/${_pkgname}
)
add_dependencies(package package_prep)

add_custom_target(package_zip
        COMMAND ${CMAKE_COMMAND} -E tar cf ${CMAKE_BINARY_DIR}/${_pkgname}.zip --format=zip -- ${CMAKE_BINARY_DIR}/${_pkgname}
)
add_dependencies(package_zip package_prep)






