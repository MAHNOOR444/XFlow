#include <gtest/gtest.h>
#include "sip_parser.h"

TEST(SipParserTest, IsSipPayloadIdentification) {
    const std::string sip_invite = "INVITE sip:test@10.0.2.15:5060 SIP/2.0\r\n";
    EXPECT_TRUE(net::SipParser::is_sip_payload(reinterpret_cast<const uint8_t*>(sip_invite.data()), sip_invite.size()));

    const std::string sip_status = "SIP/2.0 200 OK\r\n";
    EXPECT_TRUE(net::SipParser::is_sip_payload(reinterpret_cast<const uint8_t*>(sip_status.data()), sip_status.size()));

    const std::string rtp_or_raw = "\x80\x00\x00\x01\x00\x00\x00\x00\x12\x34\x56\x78";
    EXPECT_FALSE(net::SipParser::is_sip_payload(reinterpret_cast<const uint8_t*>(rtp_or_raw.data()), rtp_or_raw.size()));
}

TEST(SipParserTest, ExtractSipFields) {
    const std::string sample_sip = 
        "INVITE sip:test@10.0.2.15:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.2.20:5060;branch=z9hG4bK-24411-1-0\r\n"
        "From: \"G729/8000\" <sip:sipp@10.0.2.20:5060>;tag=1\r\n"
        "To: test <sip:test@10.0.2.15:5060>\r\n"
        "Call-ID: 1-24411@10.0.2.20\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";

    SipRecord record;
    bool success = net::SipParser::parse_sip_message(
        reinterpret_cast<const uint8_t*>(sample_sip.data()), sample_sip.size(), 1, record);

    EXPECT_TRUE(success);
    EXPECT_EQ(record.packet_number, 1);
    EXPECT_EQ(record.method_or_status, "INVITE sip:test@10.0.2.15:5060 SIP/2.0");
    EXPECT_EQ(record.from_field, "\"G729/8000\" <sip:sipp@10.0.2.20:5060>;tag=1");
    EXPECT_EQ(record.to_field, "test <sip:test@10.0.2.15:5060>");
    EXPECT_EQ(record.call_id, "1-24411@10.0.2.20");
}

TEST(SipParserTest, ModifyFromHeaderWithPrefix) {
    const std::string sample_sip = 
        "INVITE sip:test@10.0.2.15:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.2.20:5060;branch=z9hG4bK-24411-1-0\r\n"
        "From: \"G729/8000\" <sip:sipp@10.0.2.20:5060>;tag=1\r\n"
        "To: test <sip:test@10.0.2.15:5060>\r\n"
        "Call-ID: 1-24411@10.0.2.20\r\n"
        "\r\n"
        "v=0\r\ns=test\r\n";

    std::string modified_from;
    std::string result = net::SipParser::modify_from_header(
        reinterpret_cast<const uint8_t*>(sample_sip.data()), sample_sip.size(), "Mahnoor", modified_from);

    EXPECT_EQ(modified_from, "Mahnoor\"G729/8000\" <sip:sipp@10.0.2.20:5060>;tag=1");
    EXPECT_NE(result.find("From: Mahnoor\"G729/8000\" <sip:sipp@10.0.2.20:5060>;tag=1\r\n"), std::string::npos);
    EXPECT_NE(result.find("To: test <sip:test@10.0.2.15:5060>\r\n"), std::string::npos);
    EXPECT_NE(result.find("Call-ID: 1-24411@10.0.2.20\r\n"), std::string::npos);
    EXPECT_NE(result.find("\r\nv=0\r\ns=test\r\n"), std::string::npos);
}
