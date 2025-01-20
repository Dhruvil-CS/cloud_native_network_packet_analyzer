#include <iostream>
#include <string>
#include <cstring>
#include <pcap.h>
#include "PacketSniffer.h"
#include <thread>
#include "RestAPI.h"

void printUsage() {
    std::cout << "Usage: sudo ./cloud_native_network_packet_analyzer --interface <interface> --protocol <protocol>\n";
    std::cout << "Example: sudo ./cloud_native_network_packet_analyzer --interface en0 --protocol TCP\n";
}

int main(int argc, char* argv[]) {
    std::string interface;
    std::string protocol;

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--interface") == 0 && i + 1 < argc) {
            interface = argv[++i];
        } else if (strcmp(argv[i], "--protocol") == 0 && i + 1 < argc) {
            protocol = argv[++i];
        }
    }

    // Validate inputs
    if (interface.empty() || protocol.empty()) {
        printUsage();
        return 1;
    }

    // Convert protocol to lowercase for consistency
    for (auto& c : protocol) {
        c = tolower(c);
    }

    // Supported protocols
    if (protocol != "tcp" && protocol != "udp" && protocol != "icmp") {
        std::cerr << "Unsupported protocol: " << protocol << "\n";
        printUsage();
        return 1;
    }

    // Start the sniffer
    PacketSniffer sniffer(interface, protocol);
    // sniffer.startSniffing();
    std::thread snifferThread([&]() {
        sniffer.startSniffing();
    });
    RestAPI api;
    api.startServer(5050);  // Start the REST API server on port 5050

    snifferThread.join();

    return 0;
}
