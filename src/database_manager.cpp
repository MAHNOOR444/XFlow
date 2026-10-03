#include "database_manager.h"
#include <iostream>

namespace db {

DatabaseManager::DatabaseManager() : db_(nullptr) {}

DatabaseManager::DatabaseManager(const std::string& db_path) : db_(nullptr) {
    open(db_path);
}

DatabaseManager::~DatabaseManager() {
    close();
}

bool DatabaseManager::open(const std::string& db_path) {
    close();
    db_path_ = db_path;
    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::cerr << "[DatabaseManager] Failed to open SQLite database " << db_path << ": " << sqlite3_errmsg(db_) << std::endl;
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }
    return initialize_schema();
}

void DatabaseManager::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool DatabaseManager::initialize_schema() {
    if (!db_) return false;

    const char* schema_sql =
        "CREATE TABLE IF NOT EXISTS sip_records ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  packet_number INTEGER NOT NULL,"
        "  method_or_status TEXT,"
        "  from_field TEXT NOT NULL,"
        "  to_field TEXT NOT NULL,"
        "  call_id TEXT NOT NULL,"
        "  modified_from TEXT,"
        "  created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");";

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, schema_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "[DatabaseManager] Schema initialization failed: " << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg) sqlite3_free(err_msg);
        return false;
    }
    return true;
}

bool DatabaseManager::insert_sip_record(const SipRecord& record) {
    if (!db_) return false;

    const char* sql = "INSERT INTO sip_records (packet_number, method_or_status, from_field, to_field, call_id, modified_from) "
                      "VALUES (?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[DatabaseManager] Failed to prepare insert: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    sqlite3_bind_int(stmt, 1, record.packet_number);
    sqlite3_bind_text(stmt, 2, record.method_or_status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, record.from_field.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, record.to_field.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, record.call_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, record.modified_from.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        std::cerr << "[DatabaseManager] Insert execution failed: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }
    return true;
}

bool DatabaseManager::insert_sip_records(const std::vector<SipRecord>& records) {
    if (!db_) return false;

    // Use a transaction for bulk insert efficiency
    char* err_msg = nullptr;
    sqlite3_exec(db_, "BEGIN TRANSACTION;", nullptr, nullptr, &err_msg);
    if (err_msg) sqlite3_free(err_msg);

    for (const auto& record : records) {
        if (!insert_sip_record(record)) {
            sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
            return false;
        }
    }

    sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &err_msg);
    if (err_msg) sqlite3_free(err_msg);
    return true;
}

std::vector<SipRecord> DatabaseManager::query_all() {
    std::vector<SipRecord> results;
    if (!db_) return results;

    const char* sql = "SELECT packet_number, method_or_status, from_field, to_field, call_id, modified_from "
                      "FROM sip_records ORDER BY packet_number ASC;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return results;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        SipRecord r;
        r.packet_number = sqlite3_column_int(stmt, 0);
        const unsigned char* col1 = sqlite3_column_text(stmt, 1);
        const unsigned char* col2 = sqlite3_column_text(stmt, 2);
        const unsigned char* col3 = sqlite3_column_text(stmt, 3);
        const unsigned char* col4 = sqlite3_column_text(stmt, 4);
        const unsigned char* col5 = sqlite3_column_text(stmt, 5);

        if (col1) r.method_or_status = reinterpret_cast<const char*>(col1);
        if (col2) r.from_field = reinterpret_cast<const char*>(col2);
        if (col3) r.to_field = reinterpret_cast<const char*>(col3);
        if (col4) r.call_id = reinterpret_cast<const char*>(col4);
        if (col5) r.modified_from = reinterpret_cast<const char*>(col5);

        results.push_back(r);
    }
    sqlite3_finalize(stmt);
    return results;
}

std::vector<SipRecord> DatabaseManager::query_by_call_id(const std::string& call_id) {
    std::vector<SipRecord> results;
    if (!db_) return results;

    const char* sql = "SELECT packet_number, method_or_status, from_field, to_field, call_id, modified_from "
                      "FROM sip_records WHERE call_id = ? ORDER BY packet_number ASC;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return results;

    sqlite3_bind_text(stmt, 1, call_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        SipRecord r;
        r.packet_number = sqlite3_column_int(stmt, 0);
        const unsigned char* col1 = sqlite3_column_text(stmt, 1);
        const unsigned char* col2 = sqlite3_column_text(stmt, 2);
        const unsigned char* col3 = sqlite3_column_text(stmt, 3);
        const unsigned char* col4 = sqlite3_column_text(stmt, 4);
        const unsigned char* col5 = sqlite3_column_text(stmt, 5);

        if (col1) r.method_or_status = reinterpret_cast<const char*>(col1);
        if (col2) r.from_field = reinterpret_cast<const char*>(col2);
        if (col3) r.to_field = reinterpret_cast<const char*>(col3);
        if (col4) r.call_id = reinterpret_cast<const char*>(col4);
        if (col5) r.modified_from = reinterpret_cast<const char*>(col5);

        results.push_back(r);
    }
    sqlite3_finalize(stmt);
    return results;
}

int DatabaseManager::get_record_count() {
    if (!db_) return -1;
    const char* sql = "SELECT COUNT(*) FROM sip_records;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return -1;

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

} // namespace db
