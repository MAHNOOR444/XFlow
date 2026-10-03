#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H

#include <cstdint>
#include <cstring>
#include <string>

#if defined(_WIN32) || defined(_WIN64)
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

#pragma pack(push, 1)

struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

struct IPv4Header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fo;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;

    uint8_t get_ihl() const {
        return (version_ihl & 0x0F) * 4;
    }

    uint8_t get_version() const {
        return (version_ihl >> 4) & 0x0F;
    }
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

struct IPv4PseudoHeader {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t udp_length;
};

#pragma pack(pop)

struct SipRecord {
    int packet_number;
    std::string method_or_status;
    std::string from_field;
    std::string to_field;
    std::string call_id;
    std::string modified_from;
};

#endif
