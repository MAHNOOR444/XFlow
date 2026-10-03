#include <gtest/gtest.h>
#include "pcap_processor.h"
#include <fstream>

TEST(PcapProcessorTest, ProcessPcapEndToEnd) {
    const std::string input_pcap = "sip-rtp-g729a.pcap";
    const std::string output_pcap = "test_output.pcap";
    const std::string prefix = "Mahnoor";

    // Ensure input file exists
    std::ifstream infile(input_pcap, std::ios::binary);
    if (!infile.is_open()) {
        GTEST_SKIP() << "Input PCAP file " << input_pcap << " not found in working directory.";
    }
    infile.close();

    net::PcapProcessor processor;
    bool success = processor.process_file(input_pcap, output_pcap, prefix);
    EXPECT_TRUE(success);

    const auto& stats = processor.get_stats();
    EXPECT_EQ(stats.total_packets, 433);
    EXPECT_EQ(stats.sip_packets, 6);
    EXPECT_EQ(stats.rtp_packets, 425);
    EXPECT_EQ(stats.other_packets, 2);

    const auto& records = processor.get_records();
    ASSERT_EQ(records.size(), 6);

    // Verify first record
    EXPECT_EQ(records[0].packet_number, 1);
    EXPECT_EQ(records[0].call_id, "1-24411@10.0.2.20");
    EXPECT_EQ(records[0].from_field, "\"G729/8000\" <sip:sipp@10.0.2.20:5060>;tag=1");
    EXPECT_EQ(records[0].modified_from, "Mahnoor\"G729/8000\" <sip:sipp@10.0.2.20:5060>;tag=1");

    // Clean up test output file
    std::remove(output_pcap.c_str());
}
