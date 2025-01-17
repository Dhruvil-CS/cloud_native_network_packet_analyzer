#include "PacketParser.h"
#include <arpa/inet.h>
#include <sstream>
#include <arpa/inet.h>
#include <netinet/tcp.h>  // For TCP headers
#include <netinet/udp.h>  // For UDP headers

// Constructor initializes variables
PacketParser::PacketParser(const u_char* packet, unsigned int length)
    : packet(packet), length(length), ipHeader(nullptr), tcpHeader(nullptr), udpHeader(nullptr), icmpHeader(nullptr) {}

// Packet parsing logic
void PacketParser::parsePacket() {
    ipHeader = (struct ip*)(packet + 14);  // Skip Ethernet header
    if (ipHeader->ip_p == IPPROTO_TCP) {
        tcpHeader = (struct tcphdr*)(packet + 14 + ipHeader->ip_hl * 4);
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        udpHeader = (struct udphdr*)(packet + 14 + ipHeader->ip_hl * 4);
    } else if (ipHeader->ip_p == IPPROTO_ICMP) {
        icmpHeader = (struct icmp*)(packet + 14 + ipHeader->ip_hl * 4);
    }
}

// Returns the packet's length
unsigned int PacketParser::getPacketLength() const{
    return length;  // Return the stored length
}

// Remaining methods (isTCP, isUDP, etc.)
bool PacketParser::isTCP() const{
    return ipHeader && ipHeader->ip_p == IPPROTO_TCP;
}

bool PacketParser::isUDP() const{
    return ipHeader && ipHeader->ip_p == IPPROTO_UDP;
}

bool PacketParser::isICMP() const{
    return ipHeader && ipHeader->ip_p == IPPROTO_ICMP;
}

std::string PacketParser::getSrcIP() {
    return ipHeader ? inet_ntoa(ipHeader->ip_src) : "";
}

std::string PacketParser::getDstIP() {
    return ipHeader ? inet_ntoa(ipHeader->ip_dst) : "";
}
std::string PacketParser::getTCPDetails() const {
    if (!isTCP()) return "Not a TCP packet.";
    std::stringstream details;
    details << "TCP Source Port: " << ntohs(tcpHeader->th_sport)
            << ", TCP Destination Port: " << ntohs(tcpHeader->th_dport);
    return details.str();
}

std::string PacketParser::getUDPDetails() const {
    if (!isUDP()) return "Not a UDP packet.";
    std::stringstream details;
    details << "UDP Source Port: " << ntohs(udpHeader->uh_sport)
            << ", UDP Destination Port: " << ntohs(udpHeader->uh_dport);
    return details.str();
}

std::string PacketParser::getICMPDetails() const {
    if (!isICMP()) return "Not an ICMP packet.";
    std::stringstream details;
    details << "ICMP Type: " << (unsigned int)icmpHeader->icmp_type
            << ", ICMP Code: " << (unsigned int)icmpHeader->icmp_code;
    return details.str();
}