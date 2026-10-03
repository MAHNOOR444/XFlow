#ifndef SIP_PARSER_H
#define SIP_PARSER_H

#include <string>
#include <vector>
#include <optional>
#include "packet_headers.h"

namespace net {

class SipParser {
public:
    // Check if the payload appears to be a valid SIP packet
    static bool is_sip_payload(const uint8_t* payload, size_t length);

    // Extract To, From, Call-ID and Request/Status from a SIP message
    static bool parse_sip_message(const uint8_t* payload, size_t length, int packet_number, SipRecord& out_record);

    // Modify the From header in the SIP payload by prepending the name prefix to its content
    static std::string modify_from_header(const uint8_t* payload, size_t length, const std::string& name_prefix, std::string& out_modified_from);

    // Helper to extract a header value by header name (case-insensitive)
    static std::string extract_header_value(const std::string& sip_text, const std::string& header_name);

    // Helper to trim whitespace
    static std::string trim(const std::string& str);
};

} // namespace net

#endif // SIP_PARSER_H
