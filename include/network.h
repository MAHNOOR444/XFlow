#ifndef NETWORK_H
#define NETWORK_H

#include <string>
#include <vector>
#include <cstdint>
#include "packet_headers.h"

#if defined(_WIN32) || defined(_WIN64)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET socket_t;
    #define INVALID_SOCKET_VALUE INVALID_SOCKET
    #define SOCKET_ERROR_CODE WSAGetLastError()
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    typedef int socket_t;
    #define INVALID_SOCKET_VALUE -1
    #define SOCKET_ERROR_CODE errno
#endif

namespace net {

bool init_sockets();
void cleanup_sockets();
void close_socket(socket_t sock);

bool send_message(socket_t sock, const std::string& msg);
bool receive_message(socket_t sock, std::string& out_msg);

std::string serialize_sip_records(const std::vector<SipRecord>& records);
std::vector<SipRecord> deserialize_sip_records(const std::string& data);

}

#endif
