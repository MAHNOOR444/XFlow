#ifndef SIP_PARSER_H
#define SIP_PARSER_H

#include <string>
#include <vector>
#include <optional>
#include "packet_headers.h"

namespace net {

class SipParser {
public:
    static bool is_sip_payload(const uint8_t* payload, size_t length);
    static bool parse_sip_message(const uint8_t* payload, size_t length, int packet_number, SipRecord& out_record);
    static std::string modify_from_header(const uint8_t* payload, size_t length, const std::string& name_prefix, std::string& out_modified_from);
    static std::string extract_header_value(const std::string& sip_text, const std::string& header_name);
    static std::string trim(const std::string& str);
};

}

#endif
