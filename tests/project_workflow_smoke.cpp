#include <algorithm>
#include <filesystem>
#include <iostream>
#include <string>

#include "zara/analysis/program_analysis.hpp"
#include "zara/database/project_store.hpp"
#include "zara/desktop_qt/persistence/project_repository.hpp"
#include "zara/loader/binary_image.hpp"
#include "zara/memory/address_space.hpp"
#include "zara/security/workflow.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: zara_project_workflow_smoke <binary>\n";
        return 1;
    }

    const std::filesystem::path binary_path = std::filesystem::absolute(argv[1]);
    const std::filesystem::path database_path =
        std::filesystem::temp_directory_path() / "zara_project_workflow_smoke.sqlite";
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
    if (analysis.functions.empty() || analysis.functions.front().graph.blocks().empty() ||
        analysis.functions.front().graph.blocks().front().instructions.empty()) {
        std::cerr << "expected at least one discovered function with instructions\n";
        return 4;
    }

    zara::database::ProjectStore store(database_path);
    if (!store.save_program_analysis(image, analysis, error)) {
        std::cerr << "initial save_program_analysis failed: " << error << '\n';
        return 5;
    }

    zara::desktop_qt::persistence::ProjectRepository repository(database_path);
    if (!repository.open(error)) {
        std::cerr << "repository open failed: " << error << '\n';
        return 6;
    }

    const auto run = repository.load_latest_run(error);
    if (!run.has_value()) {
        std::cerr << "load_latest_run failed: " << error << '\n';
        return 7;
    }

    const auto& first_function = analysis.functions.front();
    const auto comment_address = first_function.graph.blocks().front().instructions.front().address;

    zara::desktop_qt::persistence::CommentRecord comment;
    comment.function_entry = first_function.entry_address;
    comment.address = comment_address;
    comment.scope = "instruction";
    comment.body = "validated analyst note'; DROP TABLE user_comments; --";
    int saved_comment_id = 0;
    if (!repository.save_comment(run->run_id, comment, &saved_comment_id, error) || saved_comment_id == 0) {
        std::cerr << "save_comment failed: " << error << '\n';
        return 8;
    }

    zara::desktop_qt::persistence::TypeAnnotationRecord annotation;
    annotation.function_entry = first_function.entry_address;
    annotation.target_kind = "argument";
    annotation.symbol_name = "arg_0";
    annotation.type_name = "char* /* analyst */";
    annotation.note = "seed input buffer with \"quotes\" and ; separators";
    int saved_annotation_id = 0;
    if (!repository.save_type_annotation(run->run_id, annotation, &saved_annotation_id, error) ||
        saved_annotation_id == 0) {
        std::cerr << "save_type_annotation failed: " << error << '\n';
        return 9;
    }

    zara::desktop_qt::persistence::SymbolRenameRecord rename;
    rename.function_entry = first_function.entry_address;
    rename.address = first_function.entry_address;
    rename.target_kind = "function";
    rename.original_name = first_function.name;
    rename.renamed_name = "analyst_selected_name'; --";
    int saved_rename_id = 0;
    if (!repository.save_symbol_rename(run->run_id, rename, &saved_rename_id, error) || saved_rename_id == 0) {
        std::cerr << "save_symbol_rename failed: " << error << '\n';
        return 10;
    }

    const auto renamed_functions = repository.load_functions(run->run_id, error);
    const auto renamed_function = std::find_if(
        renamed_functions.begin(),
        renamed_functions.end(),
        [&](const zara::desktop_qt::persistence::FunctionSummary& function) {
            return function.entry_address == first_function.entry_address;
        }
    );
    if (renamed_function == renamed_functions.end() || renamed_function->name != "analyst_selected_name'; --") {
        std::cerr << "function rename did not overlay into load_functions\n";
        return 11;
    }

    const auto renamed_details = repository.load_function_details(run->run_id, first_function.entry_address, error);
    if (!renamed_details.has_value() || renamed_details->summary.name != "analyst_selected_name'; --") {
        std::cerr << "function rename did not overlay into load_function_details\n";
        return 12;
    }

    zara::security::CrashTrace trace;
    trace.input_label = "seed-a";
    trace.crash_address = comment_address;
    trace.coverage_addresses = {comment_address};
    const auto coverage_report = zara::security::Workflow::analyze_fuzzing_surface(binary_path, analysis, trace);
    if (!repository.save_coverage_report(run->run_id, trace, coverage_report, error)) {
        std::cerr << "save_coverage_report failed: " << error << '\n';
        return 13;
    }

    const auto comments = repository.load_comments(run->run_id, error);
    if (comments.empty() || comments.front().body != "validated analyst note'; DROP TABLE user_comments; --") {
        std::cerr << "comment persistence failed\n";
        return 14;
    }

    const auto annotations = repository.load_type_annotations(run->run_id, error);
    if (annotations.empty() || annotations.front().type_name != "char* /* analyst */") {
        std::cerr << "type annotation persistence failed\n";
        return 15;
    }

    const auto coverage = repository.load_latest_coverage(run->run_id, error);
    if (!coverage.has_value() || coverage->functions.empty()) {
        std::cerr << "coverage persistence failed\n";
        return 16;
    }
    if (coverage->mutation_hooks.empty() || coverage->harness_bundle.empty()) {
        std::cerr << "coverage mutation-hook or harness persistence failed\n";
        return 21;
    }

    const auto versions = repository.load_versions(error);
    if (versions.size() < 5) {
        std::cerr << "expected analysis/comment/type/rename/coverage version events\n";
        return 17;
    }

    if (!store.save_program_analysis(image, analysis, error)) {
        std::cerr << "second save_program_analysis failed: " << error << '\n';
        return 18;
    }

    const auto second_run = repository.load_latest_run(error);
    if (!second_run.has_value() || second_run->run_id <= run->run_id) {
        std::cerr << "expected a newer run after second save\n";
        return 19;
    }

    const auto carried_comments = repository.load_comments(second_run->run_id, error);
    const auto carried_annotations = repository.load_type_annotations(second_run->run_id, error);
    const auto carried_functions = repository.load_functions(second_run->run_id, error);
    const auto carried_function = std::find_if(
        carried_functions.begin(),
        carried_functions.end(),
        [&](const zara::desktop_qt::persistence::FunctionSummary& function) {
            return function.entry_address == first_function.entry_address;
        }
    );
    if (carried_comments.empty() || carried_annotations.empty() || carried_function == carried_functions.end() ||
        carried_function->name != "analyst_selected_name'; --") {
        std::cerr << "expected comments, type annotations, and renamed symbols to carry into the new run\n";
        return 20;
    }

    return 0;
}
