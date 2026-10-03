#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <cstdint>
#include <cstddef>
#include "packet_headers.h"

namespace net {

uint16_t internet_checksum(const void* data, size_t length);
uint16_t compute_ipv4_checksum(IPv4Header* ip_header);
uint16_t compute_udp_checksum(const IPv4Header* ip_header, UDPHeader* udp_header, const uint8_t* payload, size_t payload_len);

}

#endif
