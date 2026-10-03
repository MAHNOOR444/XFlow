#include <iostream>
#include <string>
#include <vector>
#include "network.h"
#include "database_manager.h"

int main(int argc, char* argv[]) {
    int port = 8088;
    std::string db_file = "sip_records.db";
    std::string pcap_to_assign = "sip-rtp-g729a.pcap";
    std::string name_prefix = "Mahnoor";

    if (argc >= 2) port = std::stoi(argv[1]);
    if (argc >= 3) db_file = argv[2];
    if (argc >= 4) pcap_to_assign = argv[3];
    if (argc >= 5) name_prefix = argv[4];

    std::cout << "====================================================\n";
    std::cout << "       xFlow Server (Task 2 & Task 3 Database)       \n";
    std::cout << "====================================================\n";
    std::cout << "[Server] Port:            " << port << "\n";
    std::cout << "[Server] Database File:   " << db_file << "\n";
    std::cout << "[Server] Assigned PCAP:   " << pcap_to_assign << "\n";
    std::cout << "[Server] Name Prefix:     " << name_prefix << "\n\n";

    if (!net::init_sockets()) {
        std::cerr << "[Server] Failed to initialize socket system\n";
        return 1;
    }

    db::DatabaseManager db_manager;
    if (!db_manager.open(db_file)) {
        std::cerr << "[Server] Failed to open SQLite database: " << db_file << std::endl;
        net::cleanup_sockets();
        return 1;
    }
    std::cout << "[Server] Database initialized successfully (" << db_file << ")\n";

    socket_t server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET_VALUE) {
        std::cerr << "[Server] Failed to create socket: " << SOCKET_ERROR_CODE << std::endl;
        net::cleanup_sockets();
        return 1;
    }

    int opt = 1;
#if defined(_WIN32) || defined(_WIN64)
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        std::cerr << "[Server] Bind failed on port " << port << ": " << SOCKET_ERROR_CODE << std::endl;
        net::close_socket(server_fd);
        net::cleanup_sockets();
        return 1;
    }

    if (listen(server_fd, 5) != 0) {
        std::cerr << "[Server] Listen failed: " << SOCKET_ERROR_CODE << std::endl;
        net::close_socket(server_fd);
        net::cleanup_sockets();
        return 1;
    }

    std::cout << "[Server] Listening on port " << port << "... Waiting for client connection.\n";

    sockaddr_in client_addr{};
    int client_addr_len = sizeof(client_addr);
    socket_t client_fd = accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len);
    if (client_fd == INVALID_SOCKET_VALUE) {
        std::cerr << "[Server] Accept failed: " << SOCKET_ERROR_CODE << std::endl;
        net::close_socket(server_fd);
        net::cleanup_sockets();
        return 1;
    }

    std::cout << "[Server] Client connected successfully!\n";

    // Task 2: Server sends PCAP file name and parameters to client
    std::string task_msg = "ASSIGN_PCAP\t" + pcap_to_assign + "\toutput_modified.pcap\t" + name_prefix;
    std::cout << "[Server] Sending task assignment to client: " << task_msg << "\n";
    if (!net::send_message(client_fd, task_msg)) {
        std::cerr << "[Server] Failed to send assignment to client\n";
        net::close_socket(client_fd);
        net::close_socket(server_fd);
        net::cleanup_sockets();
        return 1;
    }

    // Task 2: Client sends modified data back to the server
    std::cout << "[Server] Waiting for client to process PCAP and return modified data...\n";
    std::string client_response;
    if (!net::receive_message(client_fd, client_response)) {
        std::cerr << "[Server] Failed to receive response from client\n";
        net::close_socket(client_fd);
        net::close_socket(server_fd);
        net::cleanup_sockets();
        return 1;
    }

    std::cout << "[Server] Received modified data from client (" << client_response.size() << " bytes)\n";

    // Deserialize SIP records
    std::vector<SipRecord> records = net::deserialize_sip_records(client_response);
    std::cout << "[Server] Deserialized " << records.size() << " SIP records.\n";

    // Task 3: Server writes 'To', 'From', and 'Call ID' fields to the database
    std::cout << "[Server] Writing records to SQLite database...\n";
    if (db_manager.insert_sip_records(records)) {
        std::cout << "[Server] All records committed to database successfully.\n";
    } else {
        std::cerr << "[Server] Warning: Failed to insert some or all records into database.\n";
    }

    // Query database to verify
    int total_db_records = db_manager.get_record_count();
    std::cout << "[Server] Current total records in database: " << total_db_records << "\n\n";

    std::vector<SipRecord> queried = db_manager.query_all();
    std::cout << "--- Stored Database Records (" << queried.size() << ") ---\n";
    for (const auto& r : queried) {
        std::cout << "  [Pkt #" << r.packet_number << "] Call-ID: " << r.call_id << "\n";
        std::cout << "    From:          " << r.from_field << "\n";
        std::cout << "    To:            " << r.to_field << "\n";
        std::cout << "    Modified From: " << r.modified_from << "\n";
    }
    std::cout << "----------------------------------------------------\n";

    // Send ACK to client
    std::string ack_msg = "SUCCESS\tInserted " + std::to_string(records.size()) + " records into database.";
    net::send_message(client_fd, ack_msg);

    net::close_socket(client_fd);
    net::close_socket(server_fd);
    net::cleanup_sockets();

    std::cout << "[Server] Workflow completed successfully.\n";
    return 0;
}
