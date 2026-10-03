#include <gtest/gtest.h>
#include "checksum.h"
#include <vector>

TEST(ChecksumTest, BasicInternetChecksum) {
    // Known vector from RFC 1071 / standard test
    uint8_t data[] = { 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    uint16_t cs = net::internet_checksum(data, sizeof(data));
    // Verify that summing data with checksum produces 0xFFFF
    std::vector<uint8_t> with_cs(data, data + sizeof(data));
    with_cs.push_back(static_cast<uint8_t>(cs >> 8));
    with_cs.push_back(static_cast<uint8_t>(cs & 0xFF));
    uint16_t verify = net::internet_checksum(with_cs.data(), with_cs.size());
    EXPECT_EQ(verify, 0x0000);
}

TEST(ChecksumTest, IPv4HeaderChecksum) {
    // Packet 1 IPv4 header from sip-rtp-g729a.pcap
    uint8_t ip_bytes[] = {
        0x45, 0x00, 0x01, 0xea, 0xed, 0x85, 0x40, 0x00, 
        0x40, 0x11, 0x00, 0x00, // Checksum zeroed
        0x0a, 0x00, 0x02, 0x14, // 10.0.2.20
        0x0a, 0x00, 0x02, 0x0f  // 10.0.2.15
    };

    IPv4Header* ip = reinterpret_cast<IPv4Header*>(ip_bytes);
    uint16_t computed = net::compute_ipv4_checksum(ip);

    // Expected checksum in Packet 1 is 0x335b
    EXPECT_EQ(ntohs(computed), 0x335b);
    EXPECT_EQ(ip->checksum, htons(0x335b));
}

TEST(ChecksumTest, UDPChecksumRFC768) {
    // Packet 1 IPv4 and UDP setup
    uint8_t ip_bytes[] = {
        0x45, 0x00, 0x01, 0xea, 0xed, 0x85, 0x40, 0x00,
        0x40, 0x11, 0x33, 0x5b,
        0x0a, 0x00, 0x02, 0x14, // 10.0.2.20
        0x0a, 0x00, 0x02, 0x0f  // 10.0.2.15
    };
    IPv4Header* ip = reinterpret_cast<IPv4Header*>(ip_bytes);

    uint8_t udp_bytes[] = {
        0x13, 0xc4, 0x13, 0xc4, // 5060 -> 5060
        0x01, 0xd6,             // Length: 470
        0x00, 0x00              // Checksum zeroed
    };
    UDPHeader* udp = reinterpret_cast<UDPHeader*>(udp_bytes);

    // Sample payload
    const std::string test_payload = "INVITE sip:test@10.0.2.15:5060 SIP/2.0\r\n";
    uint16_t cs = net::compute_udp_checksum(ip, udp, 
        reinterpret_cast<const uint8_t*>(test_payload.data()), test_payload.size());

    EXPECT_NE(cs, 0);
    EXPECT_EQ(ntohs(udp->length), sizeof(UDPHeader) + test_payload.size());
}
