#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H
#include <fstream>
#include <string>
#include <iostream>
#include <pcap.h>
#include "PacketParser.h"  // Include the PacketParser header

// Add PacketStats class to track statistics
class PacketStats {
public:
    int totalPackets = 0;
    int tcpPackets = 0;
    int udpPackets = 0;
    int icmpPackets = 0;
    long long totalBytes = 0;

    void printStats() {
        std::cout << "\nStatistics: "
                  << "\nTotal Packets: " << totalPackets
                  << "\nTCP Packets: " << tcpPackets
                  << "\nUDP Packets: " << udpPackets
                  << "\nICMP Packets: " << icmpPackets
                  << "\nTotal Bytes: " << totalBytes << std::endl;
    }

    void updateStats(const PacketParser& parser) {
        totalPackets++;
        totalBytes += parser.getPacketLength();
        
        if (parser.isTCP()) {
            tcpPackets++;
        } else if (parser.isUDP()) {
            udpPackets++;
        } else if (parser.isICMP()) {
            icmpPackets++;
        }
    }
    void saveStatsToFile(const std::string& filename) const {
        std::ofstream file(filename);
        if (file.is_open()) {
            file << "Statistics:\n"
                 << "Total Packets: " << totalPackets << "\n"
                 << "TCP Packets: " << tcpPackets << "\n"
                 << "UDP Packets: " << udpPackets << "\n"
                 << "ICMP Packets: " << icmpPackets << "\n"
                 << "Total Bytes: " << totalBytes << "\n";
            file.close();
        } else {
            std::cerr << "Error opening file for writing statistics.\n";
        }
    }
};

// Global stats object
extern PacketStats stats;

class PacketSniffer {
public:
    PacketSniffer(const std::string& interface, const std::string& protocol);
    void startSniffing();
    static void packetHandler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);

private:
    std::string interfaceName;
    std::string protocolFilter;
};

#endif
