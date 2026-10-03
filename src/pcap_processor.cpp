#include "pcap_processor.h"
#include <iostream>
#include <vector>
#include <cstring>

namespace net {

PcapProcessor::PcapProcessor() {}

PcapProcessor::~PcapProcessor() {}

bool PcapProcessor::process_file(const std::string& input_path, const std::string& output_path, const std::string& name_prefix) {
    records_.clear();
    stats_ = PcapStats{};

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* handle = pcap_open_offline(input_path.c_str(), errbuf);
    if (!handle) {
        std::cerr << "Error opening input file " << input_path << ": " << errbuf << std::endl;
        return false;
    }

    pcap_dumper_t* dumper = pcap_dump_open(handle, output_path.c_str());
    if (!dumper) {
        std::cerr << "Error opening output file " << output_path << ": " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return false;
    }

    struct pcap_pkthdr* header = nullptr;
    const u_char* packet_data = nullptr;
    int packet_number = 0;

    while (pcap_next_ex(handle, &header, &packet_data) == 1) {
        packet_number++;
        stats_.total_packets++;

        if (header->caplen < sizeof(EthernetHeader)) {
            pcap_dump(reinterpret_cast<u_char*>(dumper), header, packet_data);
            stats_.other_packets++;
            continue;
        }

        const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(packet_data);
        uint16_t ether_type = ntohs(eth->ether_type);

        if (ether_type != 0x0800) {
            pcap_dump(reinterpret_cast<u_char*>(dumper), header, packet_data);
            stats_.other_packets++;
            continue;
        }

        size_t ip_offset = sizeof(EthernetHeader);
        if (header->caplen < ip_offset + sizeof(IPv4Header)) {
            pcap_dump(reinterpret_cast<u_char*>(dumper), header, packet_data);
            stats_.other_packets++;
            continue;
        }

        const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(packet_data + ip_offset);
        if (ip->get_version() != 4 || ip->protocol != 17) {
            pcap_dump(reinterpret_cast<u_char*>(dumper), header, packet_data);
            stats_.other_packets++;
            continue;
        }

        uint8_t ihl_bytes = ip->get_ihl();
        if (ihl_bytes < sizeof(IPv4Header) || header->caplen < ip_offset + ihl_bytes + sizeof(UDPHeader)) {
            pcap_dump(reinterpret_cast<u_char*>(dumper), header, packet_data);
            stats_.other_packets++;
            continue;
        }

        size_t udp_offset = ip_offset + ihl_bytes;
        const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(packet_data + udp_offset);
        uint16_t src_port = ntohs(udp->src_port);
        uint16_t dest_port = ntohs(udp->dest_port);

        size_t payload_offset = udp_offset + sizeof(UDPHeader);
        size_t payload_len = 0;
        if (header->caplen >= payload_offset) {
            payload_len = header->caplen - payload_offset;
        }

        const uint8_t* payload = packet_data + payload_offset;
        bool is_sip = (src_port == 5060 || dest_port == 5060) && SipParser::is_sip_payload(payload, payload_len);

        if (is_sip) {
            stats_.sip_packets++;

            SipRecord record;
            SipParser::parse_sip_message(payload, payload_len, packet_number, record);

            std::string modified_payload = SipParser::modify_from_header(payload, payload_len, name_prefix, record.modified_from);
            records_.push_back(record);

            int len_delta = static_cast<int>(modified_payload.size()) - static_cast<int>(payload_len);
            size_t new_caplen = header->caplen + len_delta;
            std::vector<uint8_t> new_packet(new_caplen);

            std::memcpy(new_packet.data(), packet_data, payload_offset);
            std::memcpy(new_packet.data() + payload_offset, modified_payload.data(), modified_payload.size());

            IPv4Header* new_ip = reinterpret_cast<IPv4Header*>(new_packet.data() + ip_offset);
            uint16_t new_ip_total_length = static_cast<uint16_t>(ihl_bytes + sizeof(UDPHeader) + modified_payload.size());
            new_ip->total_length = htons(new_ip_total_length);
            compute_ipv4_checksum(new_ip);

            UDPHeader* new_udp = reinterpret_cast<UDPHeader*>(new_packet.data() + udp_offset);
            uint16_t new_udp_length = static_cast<uint16_t>(sizeof(UDPHeader) + modified_payload.size());
            new_udp->length = htons(new_udp_length);
            compute_udp_checksum(new_ip, new_udp, reinterpret_cast<const uint8_t*>(modified_payload.data()), modified_payload.size());

            struct pcap_pkthdr new_header = *header;
            new_header.caplen = static_cast<bpf_u_int32>(new_caplen);
            new_header.len = static_cast<bpf_u_int32>(header->len + len_delta);

            pcap_dump(reinterpret_cast<u_char*>(dumper), &new_header, new_packet.data());
        } else {
            if ((src_port == 28120 && dest_port == 6000) || (src_port == 6000 && dest_port == 28120)) {
                stats_.rtp_packets++;
            } else {
                stats_.other_packets++;
            }
            pcap_dump(reinterpret_cast<u_char*>(dumper), header, packet_data);
        }
    }

    pcap_dump_close(dumper);
    pcap_close(handle);
    return true;
}

} // namespace net
