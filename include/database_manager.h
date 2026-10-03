#ifndef DATABASE_MANAGER_H
#define DATABASE_MANAGER_H

#include <string>
#include <vector>
#include <memory>
#include "packet_headers.h"
#include "sqlite3.h"

namespace db {

class DatabaseManager {
public:
    DatabaseManager();
    explicit DatabaseManager(const std::string& db_path);
    ~DatabaseManager();

    bool open(const std::string& db_path);
    bool initialize_schema();
    bool insert_sip_record(const SipRecord& record);
    bool insert_sip_records(const std::vector<SipRecord>& records);

    std::vector<SipRecord> query_all();
    std::vector<SipRecord> query_by_call_id(const std::string& call_id);
    int get_record_count();

    void close();
    bool is_open() const { return db_ != nullptr; }

private:
    sqlite3* db_ = nullptr;
    std::string db_path_;
};

} // namespace db

#endif // DATABASE_MANAGER_H
