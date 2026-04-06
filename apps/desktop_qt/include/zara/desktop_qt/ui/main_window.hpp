#pragma once

#include <cstdint>
#include <filesystem>
#include <future>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <tuple>
#include <vector>

#include <QJsonObject>
#include <QMainWindow>
#include <QSettings>

#include "zara/debugger/session.hpp"
#include "zara/desktop_qt/app/ai_settings.hpp"
#include "zara/desktop_qt/app/analysis_runner.hpp"
#include "zara/desktop_qt/persistence/project_repository.hpp"

QT_BEGIN_NAMESPACE
class QAction;
class QCloseEvent;
class QDockWidget;
class QLineEdit;
class QLabel;
class QListWidget;
class QListWidgetItem;
class QPlainTextEdit;
class QPushButton;
class QStackedWidget;
class QTabWidget;
class QTableWidget;
class QTimer;
class QToolBar;
QT_END_NAMESPACE

namespace zara::desktop_qt::app {
class WorkspaceController;
}

namespace zara::desktop_qt::ui {

class GraphView;

class MainWindow : public QMainWindow {
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    bool load_project(const std::filesystem::path& project_path, bool show_errors = true);
    bool open_binary(const std::filesystem::path& binary_path, bool show_errors = true);

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    enum ItemRoles {
        RoleKind = Qt::UserRole + 1,
        RoleDirection,
        RolePrimaryAddress,
        RoleSecondaryAddress,
        RoleLabel,
        RoleFlag
    };

    void create_actions();
    void create_layout();
    void apply_theme();
    void update_window_title();
    void show_startup_surface();
    void show_workspace_surface();
    void restore_session_state();
    void persist_session_state();
    QJsonObject workspace_payload() const;
    void apply_workspace_payload(const QJsonObject& payload, bool show_errors);

    void populate_workspace();
    void reset_function_views();
    void populate_function_auxiliary_views(std::uint64_t entry_address);
    void populate_imports_view();
    void populate_exports_view();
    void populate_strings_view();
    void populate_annotations_view();
    void populate_coverage_view();
    void populate_versions_view();
    void render_call_graph();
    void render_cfg_graph();
    void load_hex_view(std::optional<std::uint64_t> highlight_address = std::nullopt);
    void update_navigation_actions();
    void set_analysis_busy(bool busy);
    void set_debugger_running(bool running);
    void append_log(QPlainTextEdit* view, const QString& text) const;

    void record_navigation(std::uint64_t entry_address);
    bool select_function_entry(std::uint64_t entry_address, bool record_history = true);
    std::optional<std::uint64_t> find_function_containing_address(std::uint64_t address) const;
    void select_list_row(QListWidget* widget, int row);
    bool ensure_live_program_loaded(std::string& out_error);
    bool refresh_debug_snapshot(const debugger::StopEvent& stop, bool show_errors = true);
    void clear_flow_highlights();
    std::optional<std::uint64_t> block_start_for_address(std::uint64_t address) const;
    void populate_registers_view(const debugger::RegisterState& registers);
    void populate_stack_view(const debugger::RegisterState& registers);
    void populate_call_stack_view(const debugger::RegisterState& registers);
    void populate_breakpoints_view();
    void populate_threads_view();
    void populate_watch_view();
    void populate_memory_view(std::uint64_t address);
    void clear_debugger_views();
    void poll_analysis_job();
    std::optional<std::uint64_t> parse_runtime_address(const QString& text) const;
    QString format_symbol_label(std::uint64_t address) const;
    QString evaluate_watch_expression(const QString& expression) const;

    std::filesystem::path project_database_path_for_binary(const std::filesystem::path& binary_path) const;

    void open_binary_dialog();
    void open_project_dialog();
    void open_ai_settings_dialog();
    void refresh_analysis();
    void run_analysis_backend();
    void start_debugger_session();
    void continue_debugger_session();
    void step_debugger_session();
    void stop_debugger_session();
    void add_breakpoint();
    void remove_selected_breakpoint();
    void refresh_memory_pane();
    void apply_live_patch();
    void rename_selected_symbol();
    void add_comment();
    void edit_selected_comment();
    void delete_selected_comment();
    void add_type_annotation();
    void edit_selected_type_annotation();
    void delete_selected_type_annotation();
    void import_coverage_trace();
    void switch_selected_thread();
    void add_watch_expression();
    void remove_selected_watch_expression();
    void save_workspace_as();
    void load_workspace_from_file();
    void show_about_dialog();
    void navigate_back();
    void navigate_forward();
    [[nodiscard]] app::AiSettings current_ai_settings() const;
    [[nodiscard]] QString load_ai_secret(const app::AiSettings& config, QString* out_error = nullptr) const;
    [[nodiscard]] ai::AssistantOptions current_ai_options(const app::AiSettings& config, const QString& secret) const;
    [[nodiscard]] QString ai_runtime_summary(const app::AiSettings& config) const;

    void on_function_changed(QListWidgetItem* current, QListWidgetItem* previous);
    void on_call_activated(QListWidgetItem* item);
    void on_import_activated(QListWidgetItem* item);
    void on_export_activated(QListWidgetItem* item);
    void on_string_activated(QListWidgetItem* item);
    void on_xref_activated(QListWidgetItem* item);
    void on_workspace_tab_changed(int index);
    void show_error(const QString& title, const QString& message);

    QAction* open_binary_action_ = nullptr;
    QAction* open_project_action_ = nullptr;
    QAction* ai_settings_action_ = nullptr;
    QAction* refresh_action_ = nullptr;
    QAction* save_workspace_action_ = nullptr;
    QAction* load_workspace_action_ = nullptr;
    QAction* start_debugger_action_ = nullptr;
    QAction* stop_debugger_action_ = nullptr;
    QAction* live_patch_action_ = nullptr;
    QAction* rename_symbol_action_ = nullptr;
    QAction* add_comment_action_ = nullptr;
    QAction* edit_comment_action_ = nullptr;
    QAction* delete_comment_action_ = nullptr;
    QAction* add_type_action_ = nullptr;
    QAction* edit_type_action_ = nullptr;
    QAction* delete_type_action_ = nullptr;
    QAction* import_coverage_action_ = nullptr;
    QAction* back_action_ = nullptr;
    QAction* forward_action_ = nullptr;
    QAction* about_action_ = nullptr;
    QAction* quit_action_ = nullptr;
    QToolBar* workspace_toolbar_ = nullptr;
    QDockWidget* functions_dock_ = nullptr;
    QDockWidget* navigation_dock_ = nullptr;
    QDockWidget* output_dock_ = nullptr;

    QListWidget* functions_list_ = nullptr;
    QListWidget* calls_list_ = nullptr;
    QListWidget* imports_list_ = nullptr;
    QListWidget* exports_list_ = nullptr;
    QListWidget* xrefs_list_ = nullptr;
    QListWidget* strings_list_ = nullptr;

    QStackedWidget* central_stack_ = nullptr;
    QWidget* startup_page_ = nullptr;
    QLabel* startup_title_label_ = nullptr;
    QLabel* startup_summary_label_ = nullptr;
    QPushButton* startup_new_project_button_ = nullptr;
    QPushButton* startup_open_project_button_ = nullptr;
    QPushButton* startup_resume_button_ = nullptr;
    QTabWidget* workspace_tabs_ = nullptr;
    QWidget* annotations_page_ = nullptr;
    QWidget* coverage_page_ = nullptr;
    QWidget* versions_page_ = nullptr;
    QWidget* debugger_page_ = nullptr;
    QLabel* debugger_status_label_ = nullptr;
    QPlainTextEdit* overview_view_ = nullptr;
    QPlainTextEdit* summary_view_ = nullptr;
    QPlainTextEdit* disassembly_view_ = nullptr;
    QPlainTextEdit* decompiler_view_ = nullptr;
    GraphView* call_graph_view_ = nullptr;
    GraphView* cfg_graph_view_ = nullptr;
    QPlainTextEdit* hex_view_ = nullptr;
    QTableWidget* comments_table_ = nullptr;
    QTableWidget* types_table_ = nullptr;
    QPlainTextEdit* coverage_summary_view_ = nullptr;
    QTableWidget* coverage_table_ = nullptr;
    QTableWidget* versions_table_ = nullptr;
    QTableWidget* registers_table_ = nullptr;
    QTableWidget* stack_table_ = nullptr;
    QTableWidget* call_stack_table_ = nullptr;
    QTableWidget* breakpoints_table_ = nullptr;
    QTableWidget* threads_table_ = nullptr;
    QTableWidget* watch_table_ = nullptr;
    QPlainTextEdit* debugger_memory_view_ = nullptr;
    QPlainTextEdit* debugger_output_view_ = nullptr;
    QLineEdit* breakpoint_address_edit_ = nullptr;
    QLineEdit* memory_address_edit_ = nullptr;
    QLineEdit* memory_length_edit_ = nullptr;
    QLineEdit* patch_bytes_edit_ = nullptr;
    QLineEdit* watch_expression_edit_ = nullptr;
    QPushButton* continue_button_ = nullptr;
    QPushButton* step_button_ = nullptr;
    QPushButton* add_breakpoint_button_ = nullptr;
    QPushButton* remove_breakpoint_button_ = nullptr;
    QPushButton* refresh_memory_button_ = nullptr;
    QPushButton* apply_patch_button_ = nullptr;
    QPushButton* add_watch_button_ = nullptr;
    QPushButton* remove_watch_button_ = nullptr;
    QPlainTextEdit* output_view_ = nullptr;

    QTimer* analysis_poll_timer_ = nullptr;

    QSettings settings_;
    std::unique_ptr<app::WorkspaceController> controller_;
    std::optional<app::LiveProgram> live_program_;
    std::unique_ptr<std::future<app::AnalysisJobResult>> analysis_future_;
    std::unique_ptr<debugger::DebugSession> debug_session_;
    std::optional<debugger::RuntimeSnapshot> debug_snapshot_;
    std::optional<debugger::RegisterState> previous_registers_;
    std::set<std::uint64_t> breakpoint_addresses_;
    std::vector<QString> watch_expressions_;

    std::filesystem::path current_binary_path_;
    std::filesystem::path current_project_path_;

    std::optional<persistence::FunctionDetails> active_function_details_;
    std::optional<std::uint64_t> active_function_entry_;

    std::map<std::uint64_t, int> function_row_by_entry_;
    std::vector<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>> function_ranges_;
    std::map<std::uint64_t, int> import_row_by_address_;
    std::map<std::string, int> import_row_by_label_;
    std::map<std::uint64_t, int> export_row_by_address_;
    std::map<std::uint64_t, int> string_row_by_address_;

    std::vector<std::uint64_t> navigation_history_;
    int navigation_index_ = -1;
    bool suppress_history_ = false;
    std::optional<std::uint64_t> highlighted_call_source_;
    std::optional<std::uint64_t> highlighted_call_target_;
    QString highlighted_import_target_;
    std::optional<std::uint64_t> highlighted_cfg_source_block_;
    std::optional<std::uint64_t> highlighted_cfg_target_block_;
};

}  // namespace zara::desktop_qt::ui
