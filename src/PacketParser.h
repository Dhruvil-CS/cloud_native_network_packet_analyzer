#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <string>

class PacketParser {
public:
    PacketParser(const u_char* packet, unsigned int length);
    void parsePacket();
    bool isTCP() const;
    bool isUDP() const;
    bool isICMP() const;
    std::string getSrcIP();
    std::string getDstIP();
    std::string getTCPDetails() const;
    std::string getUDPDetails() const;
    std::string getICMPDetails() const;
    unsigned int getPacketLength() const; // Ensure this declaration exists

private:
    const u_char* packet;
    unsigned int length;
    struct ip* ipHeader;
    struct tcphdr* tcpHeader;
    struct udphdr* udpHeader;
    struct icmp* icmpHeader;
};

#endif
