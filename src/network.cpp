#include "network.h"
#include <iostream>
#include <sstream>
#include <vector>

namespace net {

bool init_sockets() {
#if defined(_WIN32) || defined(_WIN64)
    WSADATA wsa_data;
    int res = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (res != 0) {
        std::cerr << "[Network] WSAStartup failed: " << res << std::endl;
        return false;
    }
#endif
    return true;
}

void cleanup_sockets() {
#if defined(_WIN32) || defined(_WIN64)
    WSACleanup();
#endif
}

void close_socket(socket_t sock) {
#if defined(_WIN32) || defined(_WIN64)
    closesocket(sock);
#else
    close(sock);
#endif
}

bool send_message(socket_t sock, const std::string& msg) {
    uint32_t len = htonl(static_cast<uint32_t>(msg.size()));
    
    // Send 4-byte length prefix
    const char* len_ptr = reinterpret_cast<const char*>(&len);
    size_t total_sent = 0;
    while (total_sent < 4) {
        int sent = send(sock, len_ptr + total_sent, static_cast<int>(4 - total_sent), 0);
        if (sent <= 0) return false;
        total_sent += sent;
    }

    // Send payload
    total_sent = 0;
    while (total_sent < msg.size()) {
        int sent = send(sock, msg.data() + total_sent, static_cast<int>(msg.size() - total_sent), 0);
        if (sent <= 0) return false;
        total_sent += sent;
    }

    return true;
}

bool receive_message(socket_t sock, std::string& out_msg) {
    out_msg.clear();
    uint32_t net_len = 0;
    char* len_ptr = reinterpret_cast<char*>(&net_len);
    size_t total_recv = 0;

    // Read 4-byte length prefix
    while (total_recv < 4) {
        int bytes = recv(sock, len_ptr + total_recv, static_cast<int>(4 - total_recv), 0);
        if (bytes <= 0) return false;
        total_recv += bytes;
    }

    uint32_t msg_len = ntohl(net_len);
    if (msg_len > 10 * 1024 * 1024) { // 10 MB sanity limit
        std::cerr << "[Network] Message too large: " << msg_len << " bytes" << std::endl;
        return false;
    }

    std::vector<char> buffer(msg_len);
    total_recv = 0;
    while (total_recv < msg_len) {
        int bytes = recv(sock, buffer.data() + total_recv, static_cast<int>(msg_len - total_recv), 0);
        if (bytes <= 0) return false;
        total_recv += bytes;
    }

    out_msg.assign(buffer.data(), msg_len);
    return true;
}

std::string serialize_sip_records(const std::vector<SipRecord>& records) {
    std::ostringstream ss;
    ss << "COUNT:" << records.size() << "\n";
    for (const auto& r : records) {
        ss << "RECORD\t"
           << r.packet_number << "\t"
           << r.method_or_status << "\t"
           << r.from_field << "\t"
           << r.to_field << "\t"
           << r.call_id << "\t"
           << r.modified_from << "\n";
    }
    return ss.str();
}

std::vector<SipRecord> deserialize_sip_records(const std::string& data) {
    std::vector<SipRecord> records;
    std::istringstream ss(data);
    std::string line;

    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.rfind("RECORD\t", 0) == 0) {
            std::istringstream line_stream(line.substr(7));
            std::string part;
            std::vector<std::string> parts;
            while (std::getline(line_stream, part, '\t')) {
                parts.push_back(part);
            }
            if (parts.size() >= 6) {
                SipRecord r;
                r.packet_number = std::stoi(parts[0]);
                r.method_or_status = parts[1];
                r.from_field = parts[2];
                r.to_field = parts[3];
                r.call_id = parts[4];
                r.modified_from = parts[5];
                records.push_back(r);
            }
        }
    }
    return records;
}

} // namespace net
