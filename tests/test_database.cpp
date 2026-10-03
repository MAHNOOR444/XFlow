#include <gtest/gtest.h>
#include "database_manager.h"
#include <cstdio>

class DatabaseTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use an in-memory database for fast, isolated unit testing
        db.open(":memory:");
    }

    void TearDown() override {
        db.close();
    }

    db::DatabaseManager db;
};

// Required Unit Test: Insert records and run queries to check database correctness
TEST_F(DatabaseTest, InsertAndQueryRecords) {
    ASSERT_TRUE(db.is_open());

    SipRecord r1{1, "INVITE sip:test@10.0.2.15:5060 SIP/2.0",
                 "\"G729/8000\" <sip:sipp@10.0.2.20:5060>;tag=1",
                 "test <sip:test@10.0.2.15:5060>",
                 "1-24411@10.0.2.20",
                 "Mahnoor\"G729/8000\" <sip:sipp@10.0.2.20:5060>;tag=1"};

    SipRecord r2{432, "BYE sip:sipp@10.0.2.20:5060 SIP/2.0",
                 "test <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH",
                 "\"G729/8000\" <sip:sipp@10.0.2.20:5060>;tag=1",
                 "1-24411@10.0.2.20",
                 "Mahnoortest <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH"};

    EXPECT_TRUE(db.insert_sip_record(r1));
    EXPECT_TRUE(db.insert_sip_record(r2));

    // Test record count
    EXPECT_EQ(db.get_record_count(), 2);

    // Query all records
    auto all_records = db.query_all();
    ASSERT_EQ(all_records.size(), 2);

    EXPECT_EQ(all_records[0].packet_number, 1);
    EXPECT_EQ(all_records[0].call_id, "1-24411@10.0.2.20");
    EXPECT_EQ(all_records[0].from_field, "\"G729/8000\" <sip:sipp@10.0.2.20:5060>;tag=1");
    EXPECT_EQ(all_records[0].to_field, "test <sip:test@10.0.2.15:5060>");
    EXPECT_EQ(all_records[0].modified_from, "Mahnoor\"G729/8000\" <sip:sipp@10.0.2.20:5060>;tag=1");

    EXPECT_EQ(all_records[1].packet_number, 432);
    EXPECT_EQ(all_records[1].modified_from, "Mahnoortest <sip:test@10.0.2.15:5060>;tag=D63NF7DZQ89gH");

    // Query by Call-ID
    auto call_records = db.query_by_call_id("1-24411@10.0.2.20");
    EXPECT_EQ(call_records.size(), 2);

    auto empty_records = db.query_by_call_id("non-existent-call-id");
    EXPECT_EQ(empty_records.size(), 0);
}

// Test bulk insert transaction
TEST_F(DatabaseTest, BulkInsertRecords) {
    ASSERT_TRUE(db.is_open());

    std::vector<SipRecord> batch;
    for (int i = 1; i <= 6; ++i) {
        batch.push_back({i, "SIP/2.0 200 OK", "FromVal", "ToVal", "CallID-" + std::to_string(i), "MahnoorFromVal"});
    }

    EXPECT_TRUE(db.insert_sip_records(batch));
    EXPECT_EQ(db.get_record_count(), 6);
}
