#ifndef PCAP_PROCESSOR_H
#define PCAP_PROCESSOR_H

#include <string>
#include <vector>
#include <memory>
#include "packet_headers.h"
#include "sip_parser.h"
#include "checksum.h"

#ifdef _WIN32
    #include <pcap.h>
#else
    #include <pcap/pcap.h>
#endif

namespace net {

struct PcapStats {
    size_t total_packets = 0;
    size_t sip_packets = 0;
    size_t rtp_packets = 0;
    size_t other_packets = 0;
};

class PcapProcessor {
public:
    PcapProcessor();
    ~PcapProcessor();

    bool process_file(const std::string& input_path, const std::string& output_path, const std::string& name_prefix);

    const std::vector<SipRecord>& get_records() const { return records_; }
    const PcapStats& get_stats() const { return stats_; }

private:
    std::vector<SipRecord> records_;
    PcapStats stats_;
};

}

#endif
