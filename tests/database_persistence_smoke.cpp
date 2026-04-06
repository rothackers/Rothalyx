#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "zara/analysis/program_analysis.hpp"
#include "zara/database/project_store.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"

#if __has_include(<sqlite3.h>)
#include <sqlite3.h>
#define ZARA_TEST_HAS_SQLITE 1
#else
#define ZARA_TEST_HAS_SQLITE 0
#endif

namespace {

#if ZARA_TEST_HAS_SQLITE
bool query_text(sqlite3* database, const char* sql, std::string& out_value) {
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) != SQLITE_OK) {
        return false;
    }

    bool ok = false;
    if (sqlite3_step(statement) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(statement, 0);
        out_value = text == nullptr ? "" : reinterpret_cast<const char*>(text);
        ok = true;
    }

    sqlite3_finalize(statement);
    return ok;
}

bool query_pragma_text(sqlite3* database, const char* sql, std::string& out_value) {
    return query_text(database, sql, out_value);
}

bool table_has_column(sqlite3* database, const char* table_name, const char* column_name) {
    const std::string sql = "PRAGMA table_info(" + std::string(table_name) + ");";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(database, sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) {
        return false;
    }

    bool found = false;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(statement, 1);
        if (text != nullptr && std::string(reinterpret_cast<const char*>(text)) == column_name) {
            found = true;
            break;
        }
    }

    sqlite3_finalize(statement);
    return found;
}
#endif

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: zara_database_persistence_smoke <binary>\n";
        return 1;
    }

#if !ZARA_TEST_HAS_SQLITE
    std::cout << "sqlite headers unavailable; skipping persistence smoke\n";
    return 0;
#else
    const std::filesystem::path binary_path = std::filesystem::absolute(argv[1]);
    const std::filesystem::path database_path = std::filesystem::temp_directory_path() / "zara_persistence_smoke.sqlite";
    std::filesystem::remove(database_path);

    zara::loader::BinaryImage image;
    zara::memory::AddressSpace address_space;
    std::string error;
    if (!zara::loader::BinaryImage::load_from_file(binary_path, image, error)) {
        std::cerr << "load_from_file failed: " << error << '\n';
        return 2;
    }
    if (!address_space.map_image(image)) {
        std::cerr << "map_image failed\n";
        return 3;
    }

    const auto analysis = zara::analysis::Analyzer::analyze(image, address_space);
    zara::database::ProjectStore store(database_path);
    if (!store.save_program_analysis(image, analysis, error)) {
        std::cerr << "save_program_analysis failed: " << error << '\n';
        return 4;
    }

    sqlite3* database = nullptr;
    if (sqlite3_open(database_path.string().c_str(), &database) != SQLITE_OK) {
        std::cerr << "failed to open persisted database\n";
        sqlite3_close(database);
        return 5;
    }

    const bool has_function_pseudocode = table_has_column(database, "functions", "decompiled_pseudocode");
    const bool has_function_summary = table_has_column(database, "functions", "analysis_summary");
    const bool has_ai_patterns = table_has_column(database, "ai_function_insights", "patterns");
    const bool has_ai_vuln_hints = table_has_column(database, "ai_function_insights", "vulnerability_hints");
    const bool has_run_poc = table_has_column(database, "analysis_runs", "poc_scaffold");
    if (!has_function_pseudocode || !has_function_summary || !has_ai_patterns || !has_ai_vuln_hints || !has_run_poc) {
        std::cerr << "missing expected persisted columns\n";
        sqlite3_close(database);
        return 6;
    }

    std::string journal_mode;
    std::string schema_version;
    if (!query_pragma_text(database, "PRAGMA journal_mode;", journal_mode) ||
        !query_text(database, "SELECT value FROM project_metadata WHERE key = 'schema_version' LIMIT 1;", schema_version)) {
        std::cerr << "failed to read database pragmas or metadata\n";
        sqlite3_close(database);
        return 9;
    }

    std::string pseudocode;
    std::string summary;
    std::string poc_scaffold;
    if (!query_text(database, "SELECT decompiled_pseudocode FROM functions ORDER BY entry_address LIMIT 1;", pseudocode) ||
        !query_text(database, "SELECT analysis_summary FROM functions ORDER BY entry_address LIMIT 1;", summary) ||
        !query_text(database, "SELECT poc_scaffold FROM analysis_runs ORDER BY id DESC LIMIT 1;", poc_scaffold)) {
        std::cerr << "failed to read persisted analysis fields\n";
        sqlite3_close(database);
        return 7;
    }

    sqlite3_close(database);

    if (journal_mode != "wal" || schema_version != "4") {
        std::cerr << "unexpected sqlite journal mode or schema version metadata\n";
        return 10;
    }

    if (pseudocode.empty() || summary.empty() || poc_scaffold.find("from pwn import *") == std::string::npos) {
        std::cerr << "persisted analysis fields were unexpectedly empty\n";
        return 8;
    }

    return 0;
#endif
}
