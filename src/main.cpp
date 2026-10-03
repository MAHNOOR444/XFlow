#include <iostream>
#include <iomanip>
#include <string>
#include "pcap_processor.h"

int main(int argc, char* argv[]) {
    std::string input_pcap = "sip-rtp-g729a.pcap";
    std::string output_pcap = "output_modified.pcap";
    std::string name_prefix = "Mahnoor";

    if (argc >= 2) input_pcap = argv[1];
    if (argc >= 3) output_pcap = argv[2];
    if (argc >= 4) name_prefix = argv[3];

    std::cout << "====================================================\n";
    std::cout << "       xFlow PCAP Processor (Task 1 Standalone)      \n";
    std::cout << "====================================================\n";
    std::cout << "[Config] Input PCAP:     " << input_pcap << "\n";
    std::cout << "[Config] Output PCAP:    " << output_pcap << "\n";
    std::cout << "[Config] Name Prefix:    " << name_prefix << "\n\n";

    net::PcapProcessor processor;
    if (!processor.process_file(input_pcap, output_pcap, name_prefix)) {
        std::cerr << "[Error] Failed to process PCAP file: " << input_pcap << std::endl;
        return 1;
    }

    const auto& stats = processor.get_stats();
    const auto& records = processor.get_records();

    std::cout << "[Success] Processing completed successfully!\n";
    std::cout << "----------------------------------------------------\n";
    std::cout << " Statistics:\n";
    std::cout << "   Total Packets:      " << stats.total_packets << "\n";
    std::cout << "   SIP Packets Modified:" << stats.sip_packets << "\n";
    std::cout << "   RTP Packets Preserved:" << stats.rtp_packets << "\n";
    std::cout << "   Other Packets:      " << stats.other_packets << "\n";
    std::cout << "----------------------------------------------------\n\n";

    std::cout << "Extracted SIP Headers & Modifications:\n";
    for (size_t i = 0; i < records.size(); ++i) {
        const auto& r = records[i];
        std::cout << "Packet #" << r.packet_number << " [" << r.method_or_status << "]\n";
        std::cout << "   Call-ID:       " << r.call_id << "\n";
        std::cout << "   To:            " << r.to_field << "\n";
        std::cout << "   Original From: " << r.from_field << "\n";
        std::cout << "   Modified From: " << r.modified_from << "\n";
        std::cout << "----------------------------------------------------\n";
    }

    std::cout << "Output saved to: " << output_pcap << "\n";
    return 0;
}
