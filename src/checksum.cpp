#include "checksum.h"
#include <vector>

namespace net {

uint16_t internet_checksum(const void* data, size_t length) {
    uint32_t sum = 0;
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    size_t i = 0;

    for (; i + 1 < length; i += 2) {
        uint16_t word = (static_cast<uint16_t>(bytes[i]) << 8) | static_cast<uint16_t>(bytes[i + 1]);
        sum += word;
    }

    if (i < length) {
        uint16_t word = static_cast<uint16_t>(bytes[i]) << 8;
        sum += word;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    uint16_t result = static_cast<uint16_t>(~sum & 0xFFFF);
    return result;
}

uint16_t compute_ipv4_checksum(IPv4Header* ip_header) {
    if (!ip_header) return 0;
    
    // Temporarily set checksum to 0
    ip_header->checksum = 0;

    uint8_t ihl_bytes = ip_header->get_ihl();
    uint16_t cs = internet_checksum(ip_header, ihl_bytes);
    
    // Store in network byte order
    ip_header->checksum = htons(cs);
    return ip_header->checksum;
}

uint16_t compute_udp_checksum(const IPv4Header* ip_header, UDPHeader* udp_header, const uint8_t* payload, size_t payload_len) {
    if (!ip_header || !udp_header) return 0;

    // Zero out checksum field for calculation
    udp_header->checksum = 0;

    // Total UDP length (header + payload)
    uint16_t udp_len = static_cast<uint16_t>(sizeof(UDPHeader) + payload_len);
    udp_header->length = htons(udp_len);

    // Build IPv4 pseudo header
    IPv4PseudoHeader pseudo{};
    pseudo.src_ip = ip_header->src_ip;       // Already in network byte order
    pseudo.dest_ip = ip_header->dest_ip;     // Already in network byte order
    pseudo.reserved = 0;
    pseudo.protocol = ip_header->protocol;   // 17 (UDP)
    pseudo.udp_length = htons(udp_len);

    // Accumulate checksum over:
    // 1. Pseudo header (12 bytes)
    // 2. UDP header (8 bytes)
    // 3. Payload (payload_len bytes)
    std::vector<uint8_t> buffer;
    buffer.reserve(sizeof(IPv4PseudoHeader) + sizeof(UDPHeader) + payload_len);

    const uint8_t* pseudo_ptr = reinterpret_cast<const uint8_t*>(&pseudo);
    buffer.insert(buffer.end(), pseudo_ptr, pseudo_ptr + sizeof(IPv4PseudoHeader));

    const uint8_t* udp_ptr = reinterpret_cast<const uint8_t*>(udp_header);
    buffer.insert(buffer.end(), udp_ptr, udp_ptr + sizeof(UDPHeader));

    if (payload && payload_len > 0) {
        buffer.insert(buffer.end(), payload, payload + payload_len);
    }

    uint16_t cs = internet_checksum(buffer.data(), buffer.size());
    // RFC 768: If the computed checksum is zero, it is transmitted as all ones (0xFFFF)
    if (cs == 0) {
        cs = 0xFFFF;
    }

    udp_header->checksum = htons(cs);
    return udp_header->checksum;
}

} // namespace net
