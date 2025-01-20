#include "PacketSniffer.h"
#include <iostream>
#include <pcap.h>
#include <cstring>
#include <vector>
#include <mutex>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "PacketParser.h"

std::vector<std::string> PacketSniffer::capturedPackets;
std::mutex PacketSniffer::mutex;

PacketStats stats;  // Instantiate the global stats object

PacketSniffer::PacketSniffer(const std::string& interface, const std::string& protocol)
    : interfaceName(interface), protocolFilter(protocol) {}

void PacketSniffer::startSniffing() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // Open the device for capturing
    handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device:"  << errbuf << std::endl;
        return;
    }

    // Apply a BPF filter for the specified protocol
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, protocolFilter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter:"  << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        return;
    }

    std::cout << "Sniffing on interface:"  << interfaceName << ", Filter:"  << protocolFilter << std::endl;

    // Start the packet capture loop
    pcap_loop(handle, 0, PacketSniffer::packetHandler, reinterpret_cast<u_char*>(this));

    // Save stats to a file
    stats.saveStatsToFile("packet_statistics.txt");

    pcap_close(handle);

    // Cleanup
    pcap_freecode(&fp);
    pcap_close(handle);
}

void PacketSniffer::packetHandler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    auto* sniffer = reinterpret_cast<PacketSniffer*>(args);

    PacketParser parser(packet, header->len);
    parser.parsePacket();
    stats.updateStats(parser);  // Update stats
    std::cout << "\rPackets Captured: " << stats.totalPackets << std::flush;
    std::lock_guard<std::mutex> lock(mutex);
    capturedPackets.push_back("Captured packet of length " + std::to_string(header->len));
    if (parser.isTCP()) {
        std::cout << parser.getTCPDetails() << std::endl;
    } else if (parser.isUDP()) {
        std::cout << parser.getUDPDetails() << std::endl;
    } else if (parser.isICMP()) {
        std::cout << parser.getICMPDetails() << std::endl;
    }


    // Print statistics after every 100 packets
    if (stats.totalPackets % 100 == 0) {
        stats.printStats();
    }
}
std::vector<std::string> PacketSniffer::getCapturedPackets() {
    std::lock_guard<std::mutex> lock(mutex);
    return capturedPackets;
}