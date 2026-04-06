#include <QApplication>
#include <QListWidget>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <tuple>
#include <vector>

#define private public
#include "zara/desktop_qt/ui/main_window.hpp"
#undef private

#include "zara/analysis/program_analysis.hpp"
#include "zara/database/project_store.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"

namespace {

std::vector<std::byte> to_bytes(const std::vector<std::uint8_t>& values) {
    return std::vector<std::byte>(
        reinterpret_cast<const std::byte*>(values.data()),
        reinterpret_cast<const std::byte*>(values.data() + values.size())
    );
}

}  // namespace

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication application(argc, argv);

    constexpr std::uint64_t kTextBase = 0x1000;
    const std::filesystem::path database_path =
        std::filesystem::temp_directory_path() / "zara_ui_flow_highlight.sqlite";
    std::filesystem::remove(database_path);

    const std::vector<std::uint8_t> code_bytes{
        0x55,
        0x89, 0xE5,
        0x31, 0xC0,
        0x85, 0xC0,
        0x74, 0x03,
        0xE8, 0x02, 0x00, 0x00, 0x00,
        0x5D,
        0xC3,
        0x90,
        0x55,
        0x89, 0xE5,
        0x31, 0xC0,
        0x5D,
        0xC3,
    };

    const auto image = zara::loader::BinaryImage::from_components(
        "ui-flow-highlight.bin",
        zara::loader::BinaryFormat::Raw,
        zara::loader::Architecture::X86,
        kTextBase,
        kTextBase,
        {
            zara::loader::Section{
                .name = ".text",
                .virtual_address = kTextBase,
                .bytes = to_bytes(code_bytes),
                .readable = true,
                .writable = false,
                .executable = true,
            },
        }
    );

    zara::memory::AddressSpace address_space;
    if (!address_space.map_image(image)) {
        std::cerr << "failed to map synthetic UI highlight image\n";
        return 1;
    }

    const auto analysis = zara::analysis::Analyzer::analyze(image, address_space);
    if (analysis.functions.size() < 2) {
        std::cerr << "expected at least two functions in synthetic UI highlight image\n";
        return 2;
    }

    zara::database::ProjectStore store(database_path);
    std::string error;
    if (!store.save_program_analysis(image, analysis, error)) {
        std::cerr << "save_program_analysis failed: " << error << '\n';
        return 3;
    }

    zara::desktop_qt::ui::MainWindow window;
    if (!window.load_project(database_path, false)) {
        std::cerr << "load_project failed\n";
        return 4;
    }

    if (!window.select_function_entry(0x1000, false)) {
        std::cerr << "failed to select entry function\n";
        return 5;
    }

    QListWidgetItem* outgoing_call = nullptr;
    for (int index = 0; index < window.calls_list_->count(); ++index) {
        auto* item = window.calls_list_->item(index);
        if (item != nullptr &&
            item->data(window.RoleDirection).toString() == "out" &&
            item->data(window.RoleSecondaryAddress).toULongLong() == 0x1010) {
            outgoing_call = item;
            break;
        }
    }
    if (outgoing_call == nullptr) {
        std::cerr << "failed to locate outgoing call item for flow highlight\n";
        return 6;
    }

    window.on_call_activated(outgoing_call);
    if (!window.highlighted_call_source_.has_value() || !window.highlighted_call_target_.has_value() ||
        *window.highlighted_call_source_ != 0x1000 || *window.highlighted_call_target_ != 0x1010) {
        std::cerr << "call activation did not populate call-flow highlight state\n";
        return 7;
    }

    if (!window.select_function_entry(0x1000, false)) {
        std::cerr << "failed to reselect entry function for xref highlight\n";
        return 8;
    }

    QListWidgetItem* jump_xref = nullptr;
    for (int index = 0; index < window.xrefs_list_->count(); ++index) {
        auto* item = window.xrefs_list_->item(index);
        if (item != nullptr &&
            item->data(window.RoleDirection).toString() == "jump" &&
            item->data(window.RoleSecondaryAddress).toULongLong() == 0x100C) {
            jump_xref = item;
            break;
        }
    }
    if (jump_xref == nullptr) {
        std::cerr << "failed to locate jump xref item for CFG highlight\n";
        return 9;
    }

    window.on_xref_activated(jump_xref);
    if (!window.highlighted_cfg_source_block_.has_value() || !window.highlighted_cfg_target_block_.has_value()) {
        std::cerr << "xref activation did not populate CFG highlight state\n";
        return 10;
    }

    std::error_code cleanup_error;
    std::filesystem::remove(database_path, cleanup_error);
    return 0;
}
