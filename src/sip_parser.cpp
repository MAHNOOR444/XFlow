#include "sip_parser.h"
#include <sstream>
#include <algorithm>
#include <cctype>

namespace net {

static inline bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

std::string SipParser::trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

bool SipParser::is_sip_payload(const uint8_t* payload, size_t length) {
    if (!payload || length < 10) return false;
    std::string start(reinterpret_cast<const char*>(payload), (std::min)(length, size_t(32)));
    
    if (start.rfind("SIP/2.0 ", 0) == 0 ||
        start.rfind("INVITE ", 0) == 0 ||
        start.rfind("ACK ", 0) == 0 ||
        start.rfind("BYE ", 0) == 0 ||
        start.rfind("CANCEL ", 0) == 0 ||
        start.rfind("OPTIONS ", 0) == 0 ||
        start.rfind("REGISTER ", 0) == 0 ||
        start.rfind("PRACK ", 0) == 0 ||
        start.rfind("SUBSCRIBE ", 0) == 0 ||
        start.rfind("NOTIFY ", 0) == 0 ||
        start.rfind("MESSAGE ", 0) == 0 ||
        start.rfind("INFO ", 0) == 0) {
        return true;
    }
    return false;
}

std::string SipParser::extract_header_value(const std::string& sip_text, const std::string& header_name) {
    std::istringstream stream(sip_text);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            break;
        }
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = trim(line.substr(0, colon));
            if (iequals(name, header_name)) {
                return trim(line.substr(colon + 1));
            }
        }
    }
    return "";
}

bool SipParser::parse_sip_message(const uint8_t* payload, size_t length, int packet_number, SipRecord& out_record) {
    if (!is_sip_payload(payload, length)) return false;

    std::string text(reinterpret_cast<const char*>(payload), length);
    out_record.packet_number = packet_number;

    size_t first_crlf = text.find("\r\n");
    if (first_crlf != std::string::npos) {
        out_record.method_or_status = text.substr(0, first_crlf);
    } else {
        size_t first_lf = text.find('\n');
        out_record.method_or_status = (first_lf != std::string::npos) ? text.substr(0, first_lf) : text;
    }

    out_record.from_field = extract_header_value(text, "From");
    if (out_record.from_field.empty()) {
        out_record.from_field = extract_header_value(text, "f");
    }

    out_record.to_field = extract_header_value(text, "To");
    if (out_record.to_field.empty()) {
        out_record.to_field = extract_header_value(text, "t");
    }

    out_record.call_id = extract_header_value(text, "Call-ID");
    if (out_record.call_id.empty()) {
        out_record.call_id = extract_header_value(text, "Call ID");
    }
    if (out_record.call_id.empty()) {
        out_record.call_id = extract_header_value(text, "i");
    }

    return true;
}

std::string SipParser::modify_from_header(const uint8_t* payload, size_t length, const std::string& name_prefix, std::string& out_modified_from) {
    if (!payload || length == 0) return "";
    std::string text(reinterpret_cast<const char*>(payload), length);

    std::ostringstream result;
    size_t pos = 0;
    bool modified = false;

    while (pos < text.size()) {
        size_t next_pos = text.find('\n', pos);
        std::string line;

        if (next_pos != std::string::npos) {
            line = text.substr(pos, next_pos - pos + 1);
            pos = next_pos + 1;
        } else {
            line = text.substr(pos);
            pos = text.size();
        }

        if (!modified) {
            std::string line_stripped = line;
            if (!line_stripped.empty() && line_stripped.back() == '\n') line_stripped.pop_back();
            if (!line_stripped.empty() && line_stripped.back() == '\r') line_stripped.pop_back();

            if (line_stripped.empty()) {
                result << line;
                continue;
            }

            size_t colon = line_stripped.find(':');
            if (colon != std::string::npos) {
                std::string header_name = trim(line_stripped.substr(0, colon));
                if (iequals(header_name, "From") || iequals(header_name, "f")) {
                    size_t content_start = colon + 1;
                    while (content_start < line.size() && (line[content_start] == ' ' || line[content_start] == '\t')) {
                        content_start++;
                    }

                    std::string prefix_spacing = line.substr(0, content_start);
                    std::string raw_content = line.substr(content_start);

                    std::string crlf = "";
                    if (!raw_content.empty() && raw_content.back() == '\n') {
                        crlf = "\n";
                        raw_content.pop_back();
                        if (!raw_content.empty() && raw_content.back() == '\r') {
                            crlf = "\r\n";
                            raw_content.pop_back();
                        }
                    }

                    std::string new_content = name_prefix + raw_content;
                    out_modified_from = new_content;

                    line = prefix_spacing + new_content + crlf;
                    modified = true;
                }
            }
        }

        result << line;
    }

    return result.str();
}

} // namespace net
