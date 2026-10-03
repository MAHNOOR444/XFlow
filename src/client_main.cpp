#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include "network.h"
#include "pcap_processor.h"

int main(int argc, char* argv[]) {
    std::string server_ip = "127.0.0.1";
    int server_port = 8088;

    if (argc >= 2) server_ip = argv[1];
    if (argc >= 3) server_port = std::stoi(argv[2]);

    std::cout << "Connecting to server at " << server_ip << ":" << server_port << "...\n";

    if (!net::init_sockets()) {
        std::cerr << "Failed to initialize socket system\n";
        return 1;
    }

    socket_t client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd == INVALID_SOCKET_VALUE) {
        std::cerr << "Failed to create socket: " << SOCKET_ERROR_CODE << std::endl;
        net::cleanup_sockets();
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(static_cast<uint16_t>(server_port));
    inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);

    if (connect(client_fd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) != 0) {
        std::cerr << "Connection to server failed: " << SOCKET_ERROR_CODE << std::endl;
        net::close_socket(client_fd);
        net::cleanup_sockets();
        return 1;
    }

    std::cout << "Connected to server.\n";

    std::string task_msg;
    if (!net::receive_message(client_fd, task_msg)) {
        std::cerr << "Failed to receive task assignment from server\n";
        net::close_socket(client_fd);
        net::cleanup_sockets();
        return 1;
    }

    std::cout << "Received task assignment: " << task_msg << "\n";

    std::string input_pcap = "sip-rtp-g729a.pcap";
    std::string output_pcap = "output_modified.pcap";
    std::string name_prefix = "Mahnoor";

    std::istringstream iss(task_msg);
    std::string token;
    std::vector<std::string> tokens;
    while (std::getline(iss, token, '\t')) {
        tokens.push_back(token);
    }
    if (tokens.size() >= 2) input_pcap = tokens[1];
    if (tokens.size() >= 3) output_pcap = tokens[2];
    if (tokens.size() >= 4) name_prefix = tokens[3];

    std::cout << "Processing PCAP...\n";
    net::PcapProcessor processor;
    if (!processor.process_file(input_pcap, output_pcap, name_prefix)) {
        std::cerr << "Error processing PCAP file.\n";
        net::close_socket(client_fd);
        net::cleanup_sockets();
        return 1;
    }

    const auto& stats = processor.get_stats();
    const auto& records = processor.get_records();
    std::cout << "PCAP processed: " << stats.total_packets << " total packets, " 
              << stats.sip_packets << " SIP packets modified.\n";

    std::cout << "Sending extracted records to server...\n";
    std::string serialized = net::serialize_sip_records(records);
    if (!net::send_message(client_fd, serialized)) {
        std::cerr << "Failed to send records to server.\n";
        net::close_socket(client_fd);
        net::cleanup_sockets();
        return 1;
    }

    std::string ack;
    if (net::receive_message(client_fd, ack)) {
        std::cout << "Server response: " << ack << "\n";
    }

    net::close_socket(client_fd);
    net::cleanup_sockets();
    std::cout << "Client task finished.\n";
    return 0;
}
