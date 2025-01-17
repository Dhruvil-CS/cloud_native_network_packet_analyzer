cmake_minimum_required(VERSION 3.10)
project(cloud_native_network_packet_analyzer)

# Set C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add source files
set(SOURCES
    src/main.cpp
    src/PacketParser.cpp
    src/PacketSniffer.cpp
)

# Create the executable
add_executable(cloud_native_network_packet_analyzer ${SOURCES})

# Link the libpcap library
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
include_directories(${PCAP_INCLUDE_DIRS})
target_link_libraries(cloud_native_network_packet_analyzer ${PCAP_LIBRARIES})
