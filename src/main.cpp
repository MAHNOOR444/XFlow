#include <iostream>
#include <string>
#include "pcap_processor.h"

int main(int argc, char* argv[]) {
    std::string input_pcap = "sip-rtp-g729a.pcap";
    std::string output_pcap = "output_modified.pcap";
    std::string name_prefix = "Mahnoor";

    if (argc >= 2) input_pcap = argv[1];
    if (argc >= 3) output_pcap = argv[2];
    if (argc >= 4) name_prefix = argv[3];

    std::cout << "Starting PCAP processing:\n";
    std::cout << "  Input:  " << input_pcap << "\n";
    std::cout << "  Output: " << output_pcap << "\n";
    std::cout << "  Prefix: " << name_prefix << "\n\n";

    net::PcapProcessor processor;
    if (!processor.process_file(input_pcap, output_pcap, name_prefix)) {
        std::cerr << "Error: Failed to process PCAP file: " << input_pcap << std::endl;
        return 1;
    }

    const auto& stats = processor.get_stats();
    const auto& records = processor.get_records();

    std::cout << "Processing completed successfully.\n";
    std::cout << "Total packets: " << stats.total_packets << "\n";
    std::cout << "SIP packets modified: " << stats.sip_packets << "\n";
    std::cout << "RTP packets preserved: " << stats.rtp_packets << "\n";
    std::cout << "Other packets: " << stats.other_packets << "\n\n";

    std::cout << "Extracted SIP records (" << records.size() << "):\n";
    for (const auto& r : records) {
        std::cout << "Packet #" << r.packet_number << " [" << r.method_or_status << "]\n";
        std::cout << "  Call-ID: " << r.call_id << "\n";
        std::cout << "  To: " << r.to_field << "\n";
        std::cout << "  Original From: " << r.from_field << "\n";
        std::cout << "  Modified From: " << r.modified_from << "\n";
    }

    std::cout << "\nOutput saved to " << output_pcap << std::endl;
    return 0;
}
