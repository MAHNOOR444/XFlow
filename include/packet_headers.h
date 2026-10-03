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

// Ethernet Header (14 bytes)
struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type; // 0x0800 for IPv4
};

// IPv4 Header (20 bytes minimum)
struct IPv4Header {
    uint8_t version_ihl;    // 4 bits version, 4 bits header length (in 32-bit words)
    uint8_t tos;            // Type of service
    uint16_t total_length;  // Total length of IP packet (header + payload)
    uint16_t id;            // Identification
    uint16_t flags_fo;      // 3 bits flags, 13 bits fragment offset
    uint8_t ttl;            // Time to live
    uint8_t protocol;       // Protocol (17 for UDP)
    uint16_t checksum;      // Header checksum
    uint32_t src_ip;        // Source IP address
    uint32_t dest_ip;       // Destination IP address

    uint8_t get_ihl() const {
        return (version_ihl & 0x0F) * 4;
    }

    uint8_t get_version() const {
        return (version_ihl >> 4) & 0x0F;
    }
};

// UDP Header (8 bytes)
struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;        // Header + data length
    uint16_t checksum;
};

// IPv4 Pseudo Header for UDP Checksum Calculation (12 bytes)
struct IPv4PseudoHeader {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint8_t reserved;       // Always 0
    uint8_t protocol;       // 17 (UDP)
    uint16_t udp_length;    // UDP header + payload length
};

#pragma pack(pop)

// Structure to hold extracted SIP fields
struct SipRecord {
    int packet_number;
    std::string method_or_status;
    std::string from_field;
    std::string to_field;
    std::string call_id;
    std::string modified_from;
};

#endif // PACKET_HEADERS_H
