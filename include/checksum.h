#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <cstdint>
#include <cstddef>
#include "packet_headers.h"

namespace net {

// Computes standard RFC 1071 / RFC 791 16-bit Internet checksum
uint16_t internet_checksum(const void* data, size_t length);

// Computes IPv4 header checksum
uint16_t compute_ipv4_checksum(IPv4Header* ip_header);

// Computes UDP checksum over IPv4 pseudo header, UDP header, and payload
uint16_t compute_udp_checksum(const IPv4Header* ip_header, UDPHeader* udp_header, const uint8_t* payload, size_t payload_len);

} // namespace net

#endif // CHECKSUM_H
