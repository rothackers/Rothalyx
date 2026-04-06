#include "zara/desktop_qt/ui/main_window.hpp"

#include "zara/desktop_qt/app/analysis_runner.hpp"
#include "zara/desktop_qt/app/ai_settings.hpp"
#include "zara/desktop_qt/app/secret_store.hpp"
#include "zara/desktop_qt/app/workspace_controller.hpp"
#include "zara/desktop_qt/ui/graph_view.hpp"

#include <QAction>
#include <QAbstractButton>
#include <QApplication>
#include <QByteArray>
#include <QCloseEvent>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QDockWidget>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QFontDatabase>
#include <QFrame>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMenuBar>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScreen>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QSplitter>
#include <QStandardPaths>
#include <QStatusBar>
#include <QStackedWidget>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QInputDialog>
#include <QTimer>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cctype>
#include <deque>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace zara::desktop_qt::ui {

namespace {

QPlainTextEdit* make_text_surface(const QString& initial_text) {
    auto* editor = new QPlainTextEdit();
    editor->setReadOnly(true);
    editor->setPlainText(initial_text);
    editor->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    editor->setLineWrapMode(QPlainTextEdit::NoWrap);
    return editor;
}

QListWidget* make_nav_list() {
    auto* widget = new QListWidget();
    widget->setAlternatingRowColors(true);
    widget->setUniformItemSizes(true);
    widget->setLayoutMode(QListView::Batched);
    widget->setBatchSize(256);
    return widget;
}

QTableWidget* make_table_surface(const QStringList& headers) {
    auto* table = new QTableWidget();
    table->setColumnCount(headers.size());
    table->setHorizontalHeaderLabels(headers);
    table->setAlternatingRowColors(true);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setShowGrid(false);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setStretchLastSection(true);
    table->horizontalHeader()->setHighlightSections(false);
    table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    table->setWordWrap(false);
    return table;
}

QString to_qstring(const std::string& value) {
    return QString::fromStdString(value);
}

QString format_import_label(const persistence::ImportRecord& record) {
    const QString address = to_qstring(app::WorkspaceController::format_address(record.address));
    if (record.library_name.empty()) {
        return address + "  " + to_qstring(record.name);
    }
    return address + "  " + to_qstring(record.library_name) + "!" + to_qstring(record.name);
}

QString format_call_target(const persistence::CallRecord& record) {
    if (record.is_import) {
        return "<import>  " + to_qstring(record.callee_name);
    }
    return to_qstring(app::WorkspaceController::format_optional_address(record.callee_entry)) + "  " +
           to_qstring(record.callee_name);
}

QString preview_text(const std::string& value, const int max_length = 72) {
    QString text = QString::fromStdString(value).simplified();
    if (text.size() > max_length) {
        text = text.left(max_length - 3) + "...";
    }
    return text;
}

void focus_text_token(QPlainTextEdit* view, const QString& token) {
    if (view == nullptr || token.isEmpty()) {
        return;
    }
    QTextCursor cursor = view->document()->find(token);
    if (!cursor.isNull()) {
        view->setTextCursor(cursor);
        view->centerCursor();
    }
}

bool is_terminal_stop(const debugger::StopReason reason) {
    return reason == debugger::StopReason::Exited || reason == debugger::StopReason::Terminated ||
           reason == debugger::StopReason::Detached || reason == debugger::StopReason::Error;
}

QString stop_summary(const debugger::StopEvent& stop) {
    QString summary = QString("[%1] pid=%2")
                          .arg(to_qstring(std::string(debugger::to_string(stop.reason))))
                          .arg(stop.process_id);
    if (stop.thread_id > 0) {
        summary += QString("  tid=%1").arg(stop.thread_id);
    }
    if (stop.address.has_value()) {
        summary += "  @" + to_qstring(app::WorkspaceController::format_address(*stop.address));
    }
    if (stop.signal != 0) {
        summary += QString("  signal=%1").arg(stop.signal);
    }
    if (stop.exit_code != 0 || stop.reason == debugger::StopReason::Exited) {
        summary += QString("  exit=%1").arg(stop.exit_code);
    }
    if (!stop.message.empty()) {
        summary += "  " + to_qstring(stop.message);
    }
    return summary;
}

std::uint64_t read_qword(std::span<const std::byte> bytes, const std::size_t offset) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8 && offset + index < bytes.size(); ++index) {
        value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[offset + index])) << (index * 8U);
    }
    return value;
}

QString format_runtime_hex(std::uint64_t start_address, std::span<const std::byte> bytes) {
    std::ostringstream output;
    for (std::size_t offset = 0; offset < bytes.size(); offset += 16) {
        output << app::WorkspaceController::format_address(start_address + offset) << "  ";
        std::string ascii;
        for (std::size_t index = 0; index < 16; ++index) {
            if (offset + index < bytes.size()) {
                const auto byte = std::to_integer<unsigned int>(bytes[offset + index]);
                output << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << byte << ' ';
                ascii.push_back(byte >= 32U && byte < 127U ? static_cast<char>(byte) : '.');
            } else {
                output << "   ";
                ascii.push_back(' ');
            }
        }
        output << ' ' << ascii << '\n';
    }
    return QString::fromStdString(output.str());
}

bool parse_patch_bytes(const QString& text, std::vector<std::byte>& out_bytes, QString& out_error) {
    QByteArray sanitized = text.toLatin1();
    sanitized.replace(" ", "");
    sanitized.replace("\t", "");
    sanitized.replace(",", "");

    if (sanitized.isEmpty()) {
        out_error = QObject::tr("Enter one or more hex bytes.");
        return false;
    }
    if ((sanitized.size() % 2) != 0) {
        out_error = QObject::tr("Patch bytes must contain an even number of hex digits.");
        return false;
    }
    for (const auto character : sanitized) {
        if (!std::isxdigit(static_cast<unsigned char>(character))) {
            out_error = QObject::tr("Patch bytes must be hexadecimal.");
            return false;
        }
    }

    const QByteArray raw = QByteArray::fromHex(sanitized);
    out_bytes.clear();
    out_bytes.reserve(static_cast<std::size_t>(raw.size()));
    for (const auto byte : raw) {
        out_bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(byte)));
    }
    return true;
}

bool patch_overlaps_breakpoints(
    const std::uint64_t address,
    const std::size_t size,
    const std::set<std::uint64_t>& breakpoints
) {
    if (size == 0) {
        return false;
    }

    const auto end = address + static_cast<std::uint64_t>(size);
    for (const auto breakpoint : breakpoints) {
        if (breakpoint >= address && breakpoint < end) {
            return true;
        }
    }
    return false;
}

}  // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      settings_("Zara", "NativeWorkspace") {
    resize(1720, 1060);
    setDockOptions(QMainWindow::AllowNestedDocks | QMainWindow::AllowTabbedDocks | QMainWindow::AnimatedDocks);
    create_actions();
    create_layout();
    apply_theme();
    analysis_poll_timer_ = new QTimer(this);
    analysis_poll_timer_->setInterval(40);
    connect(analysis_poll_timer_, &QTimer::timeout, this, [this]() { poll_analysis_job(); });
    restore_session_state();
    update_window_title();
    update_navigation_actions();
    set_analysis_busy(false);
    set_debugger_running(false);
    statusBar()->showMessage("Native workspace shell ready", 4000);
}

MainWindow::~MainWindow() = default;

bool MainWindow::load_project(const std::filesystem::path& project_path, bool show_errors) {
    stop_debugger_session();
    auto controller = std::make_unique<app::WorkspaceController>(project_path);
    std::string error;
    if (!controller->open(error)) {
        if (show_errors) {
            show_error("Load Failed", tr("Failed to open project database.\n\n%1").arg(to_qstring(error)));
        }
        return false;
    }

    controller_ = std::move(controller);
    current_project_path_ = project_path;
    debug_snapshot_.reset();
    if (controller_->workspace() != nullptr) {
        current_binary_path_ = controller_->workspace()->run.binary_path;
    }

    populate_workspace();
    show_workspace_surface();
    statusBar()->showMessage(tr("Loaded %1").arg(QString::fromStdString(project_path.filename().string())), 5000);
    persist_session_state();
    return true;
}

bool MainWindow::open_binary(const std::filesystem::path& binary_path, bool show_errors) {
    if (!std::filesystem::exists(binary_path)) {
        if (show_errors) {
            show_error("Open Binary Failed", "The selected binary does not exist.");
        }
        return false;
    }

    stop_debugger_session();
    current_binary_path_ = binary_path;
    current_project_path_ = project_database_path_for_binary(current_binary_path_);
    live_program_.reset();
    controller_.reset();
    clear_debugger_views();
    show_workspace_surface();
    run_analysis_backend();
    return true;
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (analysis_future_ != nullptr) {
        show_error("Analysis Running", "Wait for the active analysis job to finish before closing the application.");
        event->ignore();
        return;
    }
    persist_session_state();
    stop_debugger_session();
    QMainWindow::closeEvent(event);
}

void MainWindow::create_actions() {
    open_binary_action_ = new QAction(tr("Open Binary..."), this);
    open_binary_action_->setShortcut(QKeySequence::Open);
    connect(open_binary_action_, &QAction::triggered, this, [this]() { open_binary_dialog(); });

    open_project_action_ = new QAction(tr("Open Project Database..."), this);
    open_project_action_->setShortcut(QKeySequence("Ctrl+Shift+O"));
    connect(open_project_action_, &QAction::triggered, this, [this]() { open_project_dialog(); });

    ai_settings_action_ = new QAction(tr("AI Settings..."), this);
    ai_settings_action_->setShortcut(QKeySequence("Ctrl+,"));
    connect(ai_settings_action_, &QAction::triggered, this, [this]() { open_ai_settings_dialog(); });

    refresh_action_ = new QAction(tr("Refresh Analysis"), this);
    refresh_action_->setShortcut(Qt::Key_F5);
    connect(refresh_action_, &QAction::triggered, this, [this]() { refresh_analysis(); });

    save_workspace_action_ = new QAction(tr("Save Workspace..."), this);
    save_workspace_action_->setShortcut(QKeySequence::Save);
    connect(save_workspace_action_, &QAction::triggered, this, [this]() { save_workspace_as(); });

    load_workspace_action_ = new QAction(tr("Load Workspace..."), this);
    load_workspace_action_->setShortcut(QKeySequence("Ctrl+Shift+L"));
    connect(load_workspace_action_, &QAction::triggered, this, [this]() { load_workspace_from_file(); });

    start_debugger_action_ = new QAction(tr("Start Debugger"), this);
    start_debugger_action_->setShortcut(Qt::Key_F6);
    connect(start_debugger_action_, &QAction::triggered, this, [this]() { start_debugger_session(); });

    stop_debugger_action_ = new QAction(tr("Stop Debugger"), this);
    connect(stop_debugger_action_, &QAction::triggered, this, [this]() { stop_debugger_session(); });

    live_patch_action_ = new QAction(tr("Apply Live Patch"), this);
    live_patch_action_->setShortcut(QKeySequence("Ctrl+Alt+P"));
    connect(live_patch_action_, &QAction::triggered, this, [this]() { apply_live_patch(); });

    rename_symbol_action_ = new QAction(tr("Rename Symbol"), this);
    rename_symbol_action_->setShortcut(QKeySequence(Qt::Key_F2));
    connect(rename_symbol_action_, &QAction::triggered, this, [this]() { rename_selected_symbol(); });

    add_comment_action_ = new QAction(tr("Add Comment"), this);
    add_comment_action_->setShortcut(QKeySequence("Ctrl+Shift+C"));
    connect(add_comment_action_, &QAction::triggered, this, [this]() { add_comment(); });

    edit_comment_action_ = new QAction(tr("Edit Comment"), this);
    connect(edit_comment_action_, &QAction::triggered, this, [this]() { edit_selected_comment(); });

    delete_comment_action_ = new QAction(tr("Delete Comment"), this);
    connect(delete_comment_action_, &QAction::triggered, this, [this]() { delete_selected_comment(); });

    add_type_action_ = new QAction(tr("Add Type Annotation"), this);
    add_type_action_->setShortcut(QKeySequence("Ctrl+Shift+T"));
    connect(add_type_action_, &QAction::triggered, this, [this]() { add_type_annotation(); });

    edit_type_action_ = new QAction(tr("Edit Type Annotation"), this);
    connect(edit_type_action_, &QAction::triggered, this, [this]() { edit_selected_type_annotation(); });

    delete_type_action_ = new QAction(tr("Delete Type Annotation"), this);
    connect(delete_type_action_, &QAction::triggered, this, [this]() { delete_selected_type_annotation(); });

    import_coverage_action_ = new QAction(tr("Import Coverage Trace..."), this);
    import_coverage_action_->setShortcut(QKeySequence("Ctrl+Shift+I"));
    connect(import_coverage_action_, &QAction::triggered, this, [this]() { import_coverage_trace(); });

    back_action_ = new QAction(tr("Back"), this);
    back_action_->setShortcut(QKeySequence::Back);
    connect(back_action_, &QAction::triggered, this, [this]() { navigate_back(); });

    forward_action_ = new QAction(tr("Forward"), this);
    forward_action_->setShortcut(QKeySequence::Forward);
    connect(forward_action_, &QAction::triggered, this, [this]() { navigate_forward(); });

    about_action_ = new QAction(tr("About"), this);
    connect(about_action_, &QAction::triggered, this, [this]() { show_about_dialog(); });

    quit_action_ = new QAction(tr("Quit"), this);
    quit_action_->setShortcut(QKeySequence::Quit);
    connect(quit_action_, &QAction::triggered, this, &QWidget::close);

    auto* file_menu = menuBar()->addMenu(tr("File"));
    file_menu->addAction(open_binary_action_);
    file_menu->addAction(open_project_action_);
    file_menu->addAction(refresh_action_);
    file_menu->addSeparator();
    file_menu->addAction(save_workspace_action_);
    file_menu->addAction(load_workspace_action_);
    file_menu->addSeparator();
    file_menu->addAction(quit_action_);

    auto* navigate_menu = menuBar()->addMenu(tr("Navigate"));
    navigate_menu->addAction(back_action_);
    navigate_menu->addAction(forward_action_);

    auto* settings_menu = menuBar()->addMenu(tr("Settings"));
    settings_menu->addAction(ai_settings_action_);

    auto* tools_menu = menuBar()->addMenu(tr("Tools"));
    tools_menu->addAction(start_debugger_action_);
    tools_menu->addAction(stop_debugger_action_);
    tools_menu->addAction(live_patch_action_);
    tools_menu->addSeparator();
    tools_menu->addAction(rename_symbol_action_);
    tools_menu->addSeparator();
    tools_menu->addAction(add_comment_action_);
    tools_menu->addAction(edit_comment_action_);
    tools_menu->addAction(delete_comment_action_);
    tools_menu->addSeparator();
    tools_menu->addAction(add_type_action_);
    tools_menu->addAction(edit_type_action_);
    tools_menu->addAction(delete_type_action_);
    tools_menu->addSeparator();
    tools_menu->addAction(import_coverage_action_);

    auto* help_menu = menuBar()->addMenu(tr("Help"));
    help_menu->addAction(about_action_);

    workspace_toolbar_ = addToolBar(tr("Workspace"));
    workspace_toolbar_->setObjectName("workspaceToolBar");
    workspace_toolbar_->setMovable(false);
    workspace_toolbar_->setFloatable(false);
    workspace_toolbar_->setToolButtonStyle(Qt::ToolButtonTextOnly);
    workspace_toolbar_->addAction(open_binary_action_);
    workspace_toolbar_->addAction(open_project_action_);
    workspace_toolbar_->addAction(refresh_action_);
    workspace_toolbar_->addSeparator();
    workspace_toolbar_->addAction(start_debugger_action_);
    workspace_toolbar_->addAction(stop_debugger_action_);
    workspace_toolbar_->addAction(live_patch_action_);
    workspace_toolbar_->addSeparator();
    workspace_toolbar_->addAction(rename_symbol_action_);
    workspace_toolbar_->addSeparator();
    workspace_toolbar_->addAction(add_comment_action_);
    workspace_toolbar_->addAction(add_type_action_);
    workspace_toolbar_->addAction(import_coverage_action_);
    workspace_toolbar_->addSeparator();
    workspace_toolbar_->addAction(back_action_);
    workspace_toolbar_->addAction(forward_action_);
}

void MainWindow::create_layout() {
    central_stack_ = new QStackedWidget(this);
    startup_page_ = new QWidget(this);
    startup_page_->setObjectName("startupPage");
    auto* startup_shell = new QVBoxLayout(startup_page_);
    startup_shell->setContentsMargins(28, 28, 28, 28);
    auto* startup_card = new QFrame(startup_page_);
    startup_card->setObjectName("startupCard");
    startup_card->setMinimumSize(940, 500);
    auto* startup_card_layout = new QHBoxLayout(startup_card);
    startup_card_layout->setContentsMargins(44, 42, 44, 42);
    startup_card_layout->setSpacing(36);

    auto* startup_left_column = new QVBoxLayout();
    startup_left_column->setSpacing(14);
    auto* startup_eyebrow = new QLabel(tr("NATIVE REVERSE ENGINEERING WORKSTATION"), startup_card);
    startup_eyebrow->setObjectName("startupEyebrow");
    startup_title_label_ = new QLabel(tr("ZARA RE FRAMEWORK"), startup_card);
    startup_title_label_->setObjectName("startupTitle");
    startup_title_label_->setWordWrap(true);
    auto* startup_title_support = new QLabel(
        tr("Binary analysis, graph reconstruction, decompilation, and debugger workflows in one native workstation."),
        startup_card
    );
    startup_title_support->setObjectName("startupSupport");
    startup_title_support->setWordWrap(true);
    startup_summary_label_ = new QLabel(
        tr("Open a binary to create a new project, or load an existing persisted analysis database."),
        startup_card
    );
    startup_summary_label_->setObjectName("startupSummary");
    startup_summary_label_->setWordWrap(true);
    startup_left_column->addWidget(startup_eyebrow);
    startup_left_column->addWidget(startup_title_label_);
    startup_left_column->addWidget(startup_title_support);
    startup_left_column->addStretch(1);
    startup_left_column->addWidget(startup_summary_label_);

    auto* startup_right_column = new QVBoxLayout();
    startup_right_column->setSpacing(14);
    auto* startup_actions_label = new QLabel(tr("PROJECT ENTRY"), startup_card);
    startup_actions_label->setObjectName("startupActionsLabel");
    startup_new_project_button_ = new QPushButton(tr("Create New Project"), startup_card);
    startup_new_project_button_->setObjectName("startupPrimaryButton");
    startup_new_project_button_->setMinimumHeight(54);
    startup_open_project_button_ = new QPushButton(tr("Open Existing Project"), startup_card);
    startup_open_project_button_->setObjectName("startupSecondaryButton");
    startup_open_project_button_->setMinimumHeight(50);
    startup_resume_button_ = new QPushButton(tr("Resume Last Workspace"), startup_card);
    startup_resume_button_->setObjectName("startupGhostButton");
    startup_resume_button_->setMinimumHeight(42);
    startup_right_column->addStretch(1);
    startup_right_column->addWidget(startup_actions_label);
    startup_right_column->addWidget(startup_new_project_button_);
    startup_right_column->addWidget(startup_open_project_button_);
    startup_right_column->addWidget(startup_resume_button_);
    startup_right_column->addStretch(2);
    startup_card_layout->addLayout(startup_left_column, 6);
    startup_card_layout->addLayout(startup_right_column, 5);
    startup_shell->addWidget(startup_card, 1);
    connect(startup_new_project_button_, &QPushButton::clicked, this, [this]() { open_binary_dialog(); });
    connect(startup_open_project_button_, &QPushButton::clicked, this, [this]() { open_project_dialog(); });
    connect(startup_resume_button_, &QPushButton::clicked, this, [this]() {
        const QString project_path = settings_.value("workspace/project_db").toString();
        if (!project_path.isEmpty() && QFileInfo::exists(project_path)) {
            const int tab_index = settings_.value("workspace/tab_index", 0).toInt();
            const qulonglong selected_function = settings_.value("workspace/selected_function", 0).toULongLong();
            if (load_project(std::filesystem::path(project_path.toStdString()), true)) {
                workspace_tabs_->setCurrentIndex(std::max(0, tab_index));
                if (selected_function != 0U) {
                    select_function_entry(selected_function, false);
                }
            }
        }
    });

    workspace_tabs_ = new QTabWidget(this);
    overview_view_ = make_text_surface("Overview\n\nOpen a binary or persisted project database.");
    summary_view_ = make_text_surface("Function summary\n\nSelect a function to inspect persisted analysis.");
    disassembly_view_ = make_text_surface("Disassembly\n\nSelect a function to inspect instructions.");
    decompiler_view_ = make_text_surface("Decompiler\n\nSelect a function to inspect persisted pseudocode.");
    call_graph_view_ = new GraphView("Call graph\n\nOpen a project to inspect the program call graph.", this);
    cfg_graph_view_ = new GraphView("CFG\n\nSelect a function to inspect its control-flow graph.", this);
    hex_view_ = make_text_surface("Hex view\n\nOpen a binary or project to inspect raw bytes.");
    call_graph_view_->set_node_activated_handler([this](const QString& node_id) {
        if (node_id.startsWith("import:")) {
            const auto import_name = node_id.mid(7).toStdString();
            const auto row = import_row_by_label_.find(import_name);
            if (row != import_row_by_label_.end()) {
                select_list_row(imports_list_, row->second);
            }
            return;
        }

        bool ok = false;
        const auto entry = node_id.toULongLong(&ok, 10);
        if (ok && select_function_entry(entry)) {
            workspace_tabs_->setCurrentWidget(summary_view_);
        }
    });
    cfg_graph_view_->set_node_activated_handler([this](const QString& node_id) {
        bool ok = false;
        const auto block_address = node_id.toULongLong(&ok, 0);
        if (!ok) {
            return;
        }
        workspace_tabs_->setCurrentWidget(disassembly_view_);
        focus_text_token(disassembly_view_, node_id);
        load_hex_view(block_address);
        statusBar()->showMessage(tr("Focused block %1").arg(node_id), 3000);
    });

    annotations_page_ = new QWidget(this);
    auto* annotations_layout = new QVBoxLayout(annotations_page_);
    annotations_layout->setContentsMargins(0, 0, 0, 0);
    annotations_layout->setSpacing(8);
    auto* annotation_hint = new QLabel(
        tr("Persist analyst comments and user-defined type annotations into the project database. These records carry forward into new analysis runs.")
    );
    annotation_hint->setWordWrap(true);
    comments_table_ = make_table_surface({"Address", "Scope", "Updated", "Comment"});
    types_table_ = make_table_surface({"Symbol", "Target", "Type", "Updated", "Note"});
    auto* annotation_actions = new QHBoxLayout();
    auto* add_comment_button = new QPushButton(tr("Add Comment"));
    auto* edit_comment_button = new QPushButton(tr("Edit Comment"));
    auto* delete_comment_button = new QPushButton(tr("Delete Comment"));
    auto* add_type_button = new QPushButton(tr("Add Type"));
    auto* edit_type_button = new QPushButton(tr("Edit Type"));
    auto* delete_type_button = new QPushButton(tr("Delete Type"));
    annotation_actions->addWidget(add_comment_button);
    annotation_actions->addWidget(edit_comment_button);
    annotation_actions->addWidget(delete_comment_button);
    annotation_actions->addSpacing(12);
    annotation_actions->addWidget(add_type_button);
    annotation_actions->addWidget(edit_type_button);
    annotation_actions->addWidget(delete_type_button);
    annotation_actions->addStretch(1);
    auto* annotation_splitter = new QSplitter(Qt::Vertical, annotations_page_);
    annotation_splitter->addWidget(comments_table_);
    annotation_splitter->addWidget(types_table_);
    annotation_splitter->setStretchFactor(0, 1);
    annotation_splitter->setStretchFactor(1, 1);
    annotations_layout->addWidget(annotation_hint);
    annotations_layout->addLayout(annotation_actions);
    annotations_layout->addWidget(annotation_splitter, 1);
    connect(add_comment_button, &QPushButton::clicked, this, [this]() { add_comment(); });
    connect(edit_comment_button, &QPushButton::clicked, this, [this]() { edit_selected_comment(); });
    connect(delete_comment_button, &QPushButton::clicked, this, [this]() { delete_selected_comment(); });
    connect(add_type_button, &QPushButton::clicked, this, [this]() { add_type_annotation(); });
    connect(edit_type_button, &QPushButton::clicked, this, [this]() { edit_selected_type_annotation(); });
    connect(delete_type_button, &QPushButton::clicked, this, [this]() { delete_selected_type_annotation(); });
    connect(comments_table_, &QTableWidget::itemActivated, this, [this](QTableWidgetItem*) { edit_selected_comment(); });
    connect(types_table_, &QTableWidget::itemActivated, this, [this](QTableWidgetItem*) { edit_selected_type_annotation(); });

    coverage_page_ = new QWidget(this);
    auto* coverage_layout = new QVBoxLayout(coverage_page_);
    coverage_layout->setContentsMargins(0, 0, 0, 0);
    coverage_layout->setSpacing(8);
    auto* coverage_hint = new QLabel(
        tr("Import a trace file to persist crash-to-function coverage and navigate hot code paths directly from the workspace.")
    );
    coverage_hint->setWordWrap(true);
    auto* import_coverage_button = new QPushButton(tr("Import Coverage Trace"));
    coverage_summary_view_ = make_text_surface("Coverage view\n\nImport a coverage trace to visualize execution density.");
    coverage_table_ = make_table_surface({"Function", "Entry", "Hits", "Instructions", "Coverage", "Crash"});
    coverage_layout->addWidget(coverage_hint);
    coverage_layout->addWidget(import_coverage_button, 0, Qt::AlignLeft);
    coverage_layout->addWidget(coverage_summary_view_);
    coverage_layout->addWidget(coverage_table_, 1);
    connect(import_coverage_button, &QPushButton::clicked, this, [this]() { import_coverage_trace(); });
    connect(coverage_table_, &QTableWidget::itemActivated, this, [this](QTableWidgetItem* item) {
        if (item == nullptr) {
            return;
        }
        const auto function_entry = item->data(Qt::UserRole).toULongLong();
        if (function_entry != 0U && select_function_entry(function_entry)) {
            workspace_tabs_->setCurrentWidget(summary_view_);
        }
    });

    versions_page_ = new QWidget(this);
    auto* versions_layout = new QVBoxLayout(versions_page_);
    versions_layout->setContentsMargins(0, 0, 0, 0);
    versions_layout->setSpacing(8);
    auto* versions_hint =
        new QLabel(tr("Project history records analyses, annotation edits, and imported coverage so review and audit remain attached to the binary."));
    versions_hint->setWordWrap(true);
    versions_table_ = make_table_surface({"When", "Kind", "Title", "Detail"});
    versions_layout->addWidget(versions_hint);
    versions_layout->addWidget(versions_table_, 1);

    debugger_page_ = new QWidget(this);
    auto* debugger_layout = new QVBoxLayout(debugger_page_);
    debugger_layout->setContentsMargins(0, 0, 0, 0);
    debugger_layout->setSpacing(8);
    auto* debugger_hint =
        new QLabel(tr("Native debugger panes. Launch a session, then inspect registers, stack, memory, and breakpoints."));
    debugger_hint->setWordWrap(true);
    debugger_status_label_ = new QLabel(tr("Session: idle"));
    debugger_status_label_->setObjectName("debuggerStatusLabel");
    debugger_output_view_ = make_text_surface("Debugger log\n\nStart a debugger session to inspect runtime state.");
    debugger_memory_view_ = make_text_surface("Memory pane\n\nLaunch a debugger session to read runtime memory.");
    registers_table_ = make_table_surface({"Register", "Value", "Symbol"});
    stack_table_ = make_table_surface({"Address", "Value", "Pointer"});
    call_stack_table_ = make_table_surface({"Frame", "Instruction", "Function", "Stack"});
    breakpoints_table_ = make_table_surface({"Address", "Symbol"});
    threads_table_ = make_table_surface({"Thread", "State", "IP", "Selected"});
    watch_table_ = make_table_surface({"Expression", "Value", "Detail"});
    watch_table_->setObjectName("watchTable");

    continue_button_ = new QPushButton(tr("Continue"));
    step_button_ = new QPushButton(tr("Step"));
    add_breakpoint_button_ = new QPushButton(tr("Add Breakpoint"));
    remove_breakpoint_button_ = new QPushButton(tr("Remove Breakpoint"));
    refresh_memory_button_ = new QPushButton(tr("Read Memory"));
    breakpoint_address_edit_ = new QLineEdit();
    breakpoint_address_edit_->setPlaceholderText(tr("Breakpoint address or symbol"));
    memory_address_edit_ = new QLineEdit();
    memory_address_edit_->setPlaceholderText(tr("Memory address or symbol"));
    memory_length_edit_ = new QLineEdit("128");
    memory_length_edit_->setMaximumWidth(72);
    patch_bytes_edit_ = new QLineEdit();
    patch_bytes_edit_->setPlaceholderText(tr("Patch bytes, e.g. 90 90 CC"));
    apply_patch_button_ = new QPushButton(tr("Apply Patch"));
    watch_expression_edit_ = new QLineEdit();
    watch_expression_edit_->setPlaceholderText(tr("Watch register, symbol, or address"));
    add_watch_button_ = new QPushButton(tr("Add Watch"));
    remove_watch_button_ = new QPushButton(tr("Remove Watch"));

    auto* debugger_command_row = new QHBoxLayout();
    debugger_command_row->addWidget(continue_button_);
    debugger_command_row->addWidget(step_button_);
    debugger_command_row->addSpacing(10);
    debugger_command_row->addWidget(breakpoint_address_edit_, 1);
    debugger_command_row->addWidget(add_breakpoint_button_);
    debugger_command_row->addWidget(remove_breakpoint_button_);
    debugger_command_row->addSpacing(10);
    debugger_command_row->addWidget(memory_address_edit_, 1);
    debugger_command_row->addWidget(memory_length_edit_);
    debugger_command_row->addWidget(refresh_memory_button_);
    debugger_command_row->addWidget(patch_bytes_edit_, 1);
    debugger_command_row->addWidget(apply_patch_button_);

    auto* debugger_watch_row = new QHBoxLayout();
    debugger_watch_row->addWidget(debugger_status_label_, 1);
    debugger_watch_row->addSpacing(10);
    debugger_watch_row->addWidget(watch_expression_edit_, 1);
    debugger_watch_row->addWidget(add_watch_button_);
    debugger_watch_row->addWidget(remove_watch_button_);

    auto* debugger_panes = new QTabWidget(debugger_page_);
    debugger_panes->addTab(registers_table_, tr("Registers"));
    debugger_panes->addTab(stack_table_, tr("Stack"));
    debugger_panes->addTab(call_stack_table_, tr("Call Stack"));
    debugger_panes->addTab(watch_table_, tr("Watches"));
    debugger_panes->addTab(debugger_memory_view_, tr("Memory"));
    debugger_panes->addTab(breakpoints_table_, tr("Breakpoints"));
    debugger_panes->addTab(threads_table_, tr("Threads"));

    auto* debugger_splitter = new QSplitter(Qt::Vertical, debugger_page_);
    debugger_splitter->addWidget(debugger_panes);
    debugger_splitter->addWidget(debugger_output_view_);
    debugger_splitter->setStretchFactor(0, 3);
    debugger_splitter->setStretchFactor(1, 2);

    debugger_layout->addWidget(debugger_hint);
    debugger_layout->addLayout(debugger_command_row);
    debugger_layout->addLayout(debugger_watch_row);
    debugger_layout->addWidget(debugger_splitter, 1);
    connect(continue_button_, &QPushButton::clicked, this, [this]() { continue_debugger_session(); });
    connect(step_button_, &QPushButton::clicked, this, [this]() { step_debugger_session(); });
    connect(add_breakpoint_button_, &QPushButton::clicked, this, [this]() { add_breakpoint(); });
    connect(remove_breakpoint_button_, &QPushButton::clicked, this, [this]() { remove_selected_breakpoint(); });
    connect(refresh_memory_button_, &QPushButton::clicked, this, [this]() { refresh_memory_pane(); });
    connect(apply_patch_button_, &QPushButton::clicked, this, [this]() { apply_live_patch(); });
    connect(breakpoint_address_edit_, &QLineEdit::returnPressed, this, [this]() { add_breakpoint(); });
    connect(memory_address_edit_, &QLineEdit::returnPressed, this, [this]() { refresh_memory_pane(); });
    connect(memory_length_edit_, &QLineEdit::returnPressed, this, [this]() { refresh_memory_pane(); });
    connect(patch_bytes_edit_, &QLineEdit::returnPressed, this, [this]() { apply_live_patch(); });
    connect(add_watch_button_, &QPushButton::clicked, this, [this]() { add_watch_expression(); });
    connect(remove_watch_button_, &QPushButton::clicked, this, [this]() { remove_selected_watch_expression(); });
    connect(watch_expression_edit_, &QLineEdit::returnPressed, this, [this]() { add_watch_expression(); });
    connect(registers_table_, &QTableWidget::itemActivated, this, [this](QTableWidgetItem* item) {
        if (item == nullptr) {
            return;
        }
        const auto row = item->row();
        const auto value_item = registers_table_->item(row, 1);
        if (value_item == nullptr) {
            return;
        }
        const auto address = parse_runtime_address(value_item->text());
        if (!address.has_value()) {
            return;
        }
        memory_address_edit_->setText(value_item->text());
        populate_memory_view(*address);
        if (const auto entry = find_function_containing_address(*address); entry.has_value()) {
            select_function_entry(*entry);
        }
    });
    connect(stack_table_, &QTableWidget::itemActivated, this, [this](QTableWidgetItem* item) {
        if (item == nullptr) {
            return;
        }
        const auto row = item->row();
        const auto value_item = stack_table_->item(row, 1);
        const auto address_item = stack_table_->item(row, 0);
        if (value_item == nullptr || address_item == nullptr) {
            return;
        }
        const auto address = parse_runtime_address(value_item->text());
        if (address.has_value()) {
            memory_address_edit_->setText(value_item->text());
            populate_memory_view(*address);
            if (const auto entry = find_function_containing_address(*address); entry.has_value()) {
                select_function_entry(*entry);
            }
            return;
        }
        const auto stack_address = parse_runtime_address(address_item->text());
        if (stack_address.has_value()) {
            memory_address_edit_->setText(address_item->text());
            populate_memory_view(*stack_address);
        }
    });
    connect(call_stack_table_, &QTableWidget::itemActivated, this, [this](QTableWidgetItem* item) {
        if (item == nullptr) {
            return;
        }
        const auto row = item->row();
        const auto ip_item = call_stack_table_->item(row, 1);
        if (ip_item == nullptr) {
            return;
        }
        const auto address = parse_runtime_address(ip_item->text());
        if (!address.has_value()) {
            return;
        }
        memory_address_edit_->setText(ip_item->text());
        populate_memory_view(*address);
        if (const auto entry = find_function_containing_address(*address); entry.has_value()) {
            select_function_entry(*entry);
            workspace_tabs_->setCurrentWidget(summary_view_);
        }
    });
    connect(threads_table_, &QTableWidget::itemActivated, this, [this](QTableWidgetItem*) { switch_selected_thread(); });
    connect(watch_table_, &QTableWidget::itemActivated, this, [this](QTableWidgetItem* item) {
        if (item == nullptr) {
            return;
        }
        const auto expression_item = watch_table_->item(item->row(), 0);
        if (expression_item == nullptr) {
            return;
        }
        const auto address = parse_runtime_address(expression_item->text());
        if (!address.has_value()) {
            return;
        }
        memory_address_edit_->setText(expression_item->text());
        populate_memory_view(*address);
    });
    connect(breakpoints_table_, &QTableWidget::itemActivated, this, [this](QTableWidgetItem* item) {
        if (item == nullptr) {
            return;
        }
        const auto row = item->row();
        const auto address_item = breakpoints_table_->item(row, 0);
        if (address_item == nullptr) {
            return;
        }
        const auto address = parse_runtime_address(address_item->text());
        if (address.has_value()) {
            if (const auto entry = find_function_containing_address(*address); entry.has_value()) {
                select_function_entry(*entry);
                workspace_tabs_->setCurrentWidget(summary_view_);
            }
        }
    });

    workspace_tabs_->addTab(overview_view_, tr("Overview"));
    workspace_tabs_->addTab(summary_view_, tr("Summary"));
    workspace_tabs_->addTab(disassembly_view_, tr("Disassembly"));
    workspace_tabs_->addTab(decompiler_view_, tr("Decompiler"));
    workspace_tabs_->addTab(call_graph_view_, tr("Call Graph"));
    workspace_tabs_->addTab(cfg_graph_view_, tr("CFG"));
    workspace_tabs_->addTab(hex_view_, tr("Hex"));
    workspace_tabs_->addTab(annotations_page_, tr("Annotations"));
    workspace_tabs_->addTab(coverage_page_, tr("Coverage"));
    workspace_tabs_->addTab(versions_page_, tr("Versions"));
    workspace_tabs_->addTab(debugger_page_, tr("Debugger"));
    connect(workspace_tabs_, &QTabWidget::currentChanged, this, [this](int index) { on_workspace_tab_changed(index); });
    central_stack_->addWidget(startup_page_);
    central_stack_->addWidget(workspace_tabs_);
    setCentralWidget(central_stack_);

    functions_list_ = make_nav_list();
    connect(
        functions_list_,
        &QListWidget::currentItemChanged,
        this,
        [this](QListWidgetItem* current, QListWidgetItem* previous) { on_function_changed(current, previous); }
    );

    functions_dock_ = new QDockWidget(tr("Functions"), this);
    functions_dock_->setObjectName("functionsDock");
    functions_dock_->setWidget(functions_list_);
    addDockWidget(Qt::LeftDockWidgetArea, functions_dock_);

    calls_list_ = make_nav_list();
    imports_list_ = make_nav_list();
    exports_list_ = make_nav_list();
    xrefs_list_ = make_nav_list();
    strings_list_ = make_nav_list();

    connect(calls_list_, &QListWidget::itemActivated, this, [this](QListWidgetItem* item) { on_call_activated(item); });
    connect(imports_list_, &QListWidget::itemActivated, this, [this](QListWidgetItem* item) { on_import_activated(item); });
    connect(exports_list_, &QListWidget::itemActivated, this, [this](QListWidgetItem* item) { on_export_activated(item); });
    connect(strings_list_, &QListWidget::itemActivated, this, [this](QListWidgetItem* item) { on_string_activated(item); });
    connect(xrefs_list_, &QListWidget::itemActivated, this, [this](QListWidgetItem* item) { on_xref_activated(item); });

    auto* auxiliary_tabs = new QTabWidget();
    auxiliary_tabs->addTab(calls_list_, tr("Calls"));
    auxiliary_tabs->addTab(imports_list_, tr("Imports"));
    auxiliary_tabs->addTab(exports_list_, tr("Exports"));
    auxiliary_tabs->addTab(xrefs_list_, tr("Xrefs"));
    auxiliary_tabs->addTab(strings_list_, tr("Strings"));

    navigation_dock_ = new QDockWidget(tr("Navigation"), this);
    navigation_dock_->setObjectName("navigationDock");
    navigation_dock_->setWidget(auxiliary_tabs);
    addDockWidget(Qt::RightDockWidgetArea, navigation_dock_);

    output_view_ = make_text_surface("Output log\n\nAnalysis and debugger events will appear here.");
    output_dock_ = new QDockWidget(tr("Output"), this);
    output_dock_->setObjectName("outputDock");
    output_dock_->setWidget(output_view_);
    addDockWidget(Qt::BottomDockWidgetArea, output_dock_);

    splitDockWidget(functions_dock_, output_dock_, Qt::Vertical);
    resizeDocks({functions_dock_, navigation_dock_}, {360, 360}, Qt::Horizontal);
    show_startup_surface();
}

void MainWindow::apply_theme() {
    setStyleSheet(
        "QMainWindow { background: #ECE9E1; color: #182627; }"
        "QMenuBar { background: transparent; }"
        "QToolBar { background: #F7F5F0; border: 1px solid #D9D3C7; spacing: 8px; padding: 6px; }"
        "QToolButton { padding: 8px 12px; }"
        "#startupPage { background: #E8E1D3; }"
        "#startupCard { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #FBFAF7, stop:1 #F2EEE6); border: 1px solid #D7D0C3; border-radius: 24px; }"
        "#startupEyebrow { color: #7A6A4F; letter-spacing: 0.24em; font-size: 11px; font-weight: 700; }"
        "#startupTitle { color: #142325; font-size: 42px; font-weight: 800; letter-spacing: 0.04em; }"
        "#startupSupport { color: #526063; font-size: 16px; line-height: 1.45em; }"
        "#startupSummary { color: #5B6567; font-size: 15px; line-height: 1.45em; }"
        "#startupActionsLabel { color: #7A6A4F; letter-spacing: 0.18em; font-size: 11px; font-weight: 700; }"
        "#startupPrimaryButton { background: #223033; color: #F6F4EE; padding: 12px 18px; border-radius: 12px; font-weight: 700; }"
        "#startupPrimaryButton:hover { background: #304246; }"
        "#startupSecondaryButton { background: #DDE6E0; color: #152426; padding: 12px 18px; border: 1px solid #C6D2CB; border-radius: 12px; font-weight: 700; }"
        "#startupSecondaryButton:hover { background: #D1DDD5; }"
        "#startupGhostButton { background: transparent; color: #526063; padding: 10px 18px; border: 1px solid #D7D0C3; border-radius: 12px; }"
        "#startupGhostButton:hover { background: #F1EEE7; }"
        "QTabWidget::pane, QListWidget, QPlainTextEdit, QGraphicsView, QLineEdit, QTableWidget { background: #FBFAF7; border: 1px solid #D8D2C8; }"
        "QTabBar::tab { background: #E8E2D7; padding: 9px 14px; margin-right: 4px; }"
        "QTabBar::tab:selected { background: #223033; color: #F6F4EE; }"
        "QDockWidget::title { background: #F7F5F0; border: 1px solid #D9D3C7; padding: 8px 10px; }"
        "QListWidget::item:selected { background: #DBE6E2; color: #152426; }"
        "QTableWidget::item:selected { background: #DBE6E2; color: #152426; }"
        "QPlainTextEdit { padding: 12px; }"
        "QLineEdit { padding: 10px 12px; }"
        "QPushButton { background: #223033; color: #F6F4EE; padding: 9px 14px; border: 1px solid #223033; }"
        "QPushButton:hover { background: #304246; }"
    );
}

void MainWindow::update_window_title() {
    if (controller_ == nullptr || controller_->workspace() == nullptr) {
        setWindowTitle("ZARA RE FRAMEWORK");
        return;
    }

    const auto* workspace = controller_->workspace();
    QString title = tr("ZARA RE FRAMEWORK  |  %1 / %2")
                        .arg(to_qstring(workspace->run.binary_format).toUpper(), to_qstring(workspace->run.architecture).toUpper());
    if (!current_binary_path_.empty()) {
        title += tr("  |  %1").arg(QString::fromStdString(current_binary_path_.filename().string()));
    }
    setWindowTitle(title);
}

void MainWindow::show_startup_surface() {
    if (central_stack_ != nullptr && startup_page_ != nullptr) {
        central_stack_->setCurrentWidget(startup_page_);
    }
    if (menuBar() != nullptr) {
        menuBar()->setVisible(true);
    }
    if (workspace_toolbar_ != nullptr) {
        workspace_toolbar_->setVisible(false);
    }
    if (statusBar() != nullptr) {
        statusBar()->setVisible(false);
    }
    if (functions_dock_ != nullptr) {
        functions_dock_->setVisible(false);
    }
    if (navigation_dock_ != nullptr) {
        navigation_dock_->setVisible(false);
    }
    if (output_dock_ != nullptr) {
        output_dock_->setVisible(false);
    }
    if (startup_resume_button_ != nullptr) {
        const QString project_path = settings_.value("workspace/project_db").toString();
        const bool has_recent_project = !project_path.isEmpty() && QFileInfo::exists(project_path);
        startup_resume_button_->setVisible(has_recent_project);
    }
    setWindowState(windowState() & ~(Qt::WindowMaximized | Qt::WindowFullScreen));
    resize(1040, 620);
    if (QScreen* current_screen = screen(); current_screen != nullptr) {
        const QRect available = current_screen->availableGeometry();
        move(available.center() - rect().center());
    }
    update_window_title();
}

void MainWindow::show_workspace_surface() {
    if (central_stack_ != nullptr && workspace_tabs_ != nullptr) {
        central_stack_->setCurrentWidget(workspace_tabs_);
    }
    if (menuBar() != nullptr) {
        menuBar()->setVisible(true);
    }
    if (workspace_toolbar_ != nullptr) {
        workspace_toolbar_->setVisible(true);
    }
    if (statusBar() != nullptr) {
        statusBar()->setVisible(true);
    }
    if (functions_dock_ != nullptr) {
        functions_dock_->setVisible(true);
    }
    if (navigation_dock_ != nullptr) {
        navigation_dock_->setVisible(true);
    }
    if (output_dock_ != nullptr) {
        output_dock_->setVisible(true);
    }
    if (width() < 1360 || height() < 860) {
        resize(1720, 1060);
    }
    update_window_title();
}

void MainWindow::restore_session_state() {
    const QByteArray geometry = settings_.value("workspace/geometry").toByteArray();
    const QByteArray state = settings_.value("workspace/state").toByteArray();
    if (!geometry.isEmpty()) {
        restoreGeometry(QByteArray::fromBase64(geometry));
    }
    if (!state.isEmpty()) {
        restoreState(QByteArray::fromBase64(state));
    }

    const int tab_index = settings_.value("workspace/tab_index", 0).toInt();
    const QStringList watch_values = settings_.value("workspace/watch_expressions").toStringList();
    watch_expressions_.assign(watch_values.begin(), watch_values.end());
    populate_watch_view();
    workspace_tabs_->setCurrentIndex(std::max(0, tab_index));
    show_startup_surface();
}

void MainWindow::persist_session_state() {
    settings_.setValue("workspace/geometry", saveGeometry().toBase64());
    settings_.setValue("workspace/state", saveState().toBase64());
    settings_.setValue("workspace/project_db", QString::fromStdString(current_project_path_.string()));
    settings_.setValue("workspace/binary_path", QString::fromStdString(current_binary_path_.string()));
    settings_.setValue("workspace/tab_index", workspace_tabs_->currentIndex());
    settings_.setValue("workspace/selected_function", active_function_entry_.has_value() ? QVariant::fromValue<qulonglong>(*active_function_entry_) : QVariant());
    QStringList watch_values;
    for (const auto& expression : watch_expressions_) {
        watch_values.push_back(expression);
    }
    settings_.setValue("workspace/watch_expressions", watch_values);
}

QJsonObject MainWindow::workspace_payload() const {
    QJsonObject payload;
    payload["project_db"] = QString::fromStdString(current_project_path_.string());
    payload["binary_path"] = QString::fromStdString(current_binary_path_.string());
    payload["tab_index"] = workspace_tabs_->currentIndex();
    payload["selected_function"] = active_function_entry_.has_value() ? static_cast<qint64>(*active_function_entry_) : 0;
    payload["memory_address"] = memory_address_edit_ != nullptr ? memory_address_edit_->text() : QString();
    payload["breakpoint_address"] = breakpoint_address_edit_ != nullptr ? breakpoint_address_edit_->text() : QString();
    QJsonArray watch_values;
    for (const auto& expression : watch_expressions_) {
        watch_values.push_back(expression);
    }
    payload["watch_expressions"] = watch_values;
    payload["geometry"] = QString::fromLatin1(saveGeometry().toBase64());
    payload["state"] = QString::fromLatin1(saveState().toBase64());
    return payload;
}

void MainWindow::apply_workspace_payload(const QJsonObject& payload, bool show_errors) {
    const QString project_path = payload.value("project_db").toString();
    const QString binary_path = payload.value("binary_path").toString();
    const int tab_index = payload.value("tab_index").toInt();
    const std::uint64_t selected_function = payload.value("selected_function").toVariant().toULongLong();
    if (memory_address_edit_ != nullptr) {
        memory_address_edit_->setText(payload.value("memory_address").toString());
    }
    if (breakpoint_address_edit_ != nullptr) {
        breakpoint_address_edit_->setText(payload.value("breakpoint_address").toString());
    }
    watch_expressions_.clear();
    const auto watch_values = payload.value("watch_expressions").toArray();
    for (const auto& value : watch_values) {
        if (value.isString()) {
            watch_expressions_.push_back(value.toString());
        }
    }
    populate_watch_view();

    if (!project_path.isEmpty()) {
        load_project(std::filesystem::path(project_path.toStdString()), show_errors);
    } else if (!binary_path.isEmpty()) {
        current_binary_path_ = std::filesystem::path(binary_path.toStdString());
    }

    const QString geometry = payload.value("geometry").toString();
    const QString state = payload.value("state").toString();
    if (!geometry.isEmpty()) {
        restoreGeometry(QByteArray::fromBase64(geometry.toLatin1()));
    }
    if (!state.isEmpty()) {
        restoreState(QByteArray::fromBase64(state.toLatin1()));
    }

    workspace_tabs_->setCurrentIndex(std::max(0, tab_index));
    if (selected_function != 0U) {
        select_function_entry(selected_function, false);
    }
}

void MainWindow::populate_workspace() {
    const auto previously_selected = active_function_entry_;
    const auto* active_page = workspace_tabs_ == nullptr ? nullptr : workspace_tabs_->currentWidget();
    clear_flow_highlights();
    function_row_by_entry_.clear();
    function_ranges_.clear();
    import_row_by_address_.clear();
    import_row_by_label_.clear();
    export_row_by_address_.clear();
    string_row_by_address_.clear();
    navigation_history_.clear();
    navigation_index_ = -1;
    suppress_history_ = false;

    if (controller_ == nullptr || controller_->workspace() == nullptr) {
        functions_list_->clear();
        calls_list_->clear();
        imports_list_->clear();
        exports_list_->clear();
        xrefs_list_->clear();
        strings_list_->clear();
        reset_function_views();
        call_graph_view_->show_placeholder();
        return;
    }

    const auto& workspace = *controller_->workspace();
    QSignalBlocker function_blocker(functions_list_);
    functions_list_->setUpdatesEnabled(false);
    functions_list_->clear();
    for (std::size_t index = 0; index < workspace.functions.size(); ++index) {
        const auto& function = workspace.functions[index];
        function_row_by_entry_[function.entry_address] = static_cast<int>(index);
        function_ranges_.push_back(std::make_tuple(function.start_address, function.end_address, function.entry_address));
        auto* item = new QListWidgetItem(
            QString("%1  @%2  blocks=%3  instrs=%4")
                .arg(to_qstring(function.name))
                .arg(to_qstring(app::WorkspaceController::format_address(function.entry_address)))
                .arg(function.block_count)
                .arg(function.instruction_count)
        );
        item->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(function.entry_address));
        functions_list_->addItem(item);
    }
    functions_list_->setUpdatesEnabled(true);

    std::ostringstream summary;
    summary << "Run overview\n\n";
    summary << "Project DB: " << controller_->project_path().string() << "\n";
    summary << "Binary: " << workspace.run.binary_path << "\n";
    summary << "Format: " << workspace.run.binary_format << "\n";
    summary << "Architecture: " << workspace.run.architecture << "\n";
    summary << "Base: " << app::WorkspaceController::format_address(workspace.run.base_address) << "\n";
    summary << "Entry: " << app::WorkspaceController::format_optional_address(workspace.run.entry_point) << "\n";
    summary << "Sections: " << workspace.run.section_count << "\n";
    summary << "Functions: " << workspace.run.function_count << "\n";
    summary << "Imports: " << workspace.run.import_count << "\n";
    summary << "Exports: " << workspace.run.export_count << "\n";
    summary << "Xrefs: " << workspace.run.xref_count << "\n";
    summary << "Strings: " << workspace.run.string_count << "\n";
    summary << "Comments: " << workspace.comments.size() << "\n";
    summary << "Type annotations: " << workspace.type_annotations.size() << "\n";
    summary << "Version events: " << workspace.versions.size() << "\n";
    summary << "Coverage imported: " << (workspace.coverage.has_value() ? "yes" : "no") << "\n";
    overview_view_->setPlainText(QString::fromStdString(summary.str()));

    populate_imports_view();
    populate_exports_view();
    populate_strings_view();
    {
        QSignalBlocker calls_blocker(calls_list_);
        QSignalBlocker xrefs_blocker(xrefs_list_);
        calls_list_->setUpdatesEnabled(false);
        xrefs_list_->setUpdatesEnabled(false);
        calls_list_->clear();
        xrefs_list_->clear();
        calls_list_->setUpdatesEnabled(true);
        xrefs_list_->setUpdatesEnabled(true);
    }
    reset_function_views();
    if (active_page == call_graph_view_) {
        render_call_graph();
    } else {
        call_graph_view_->show_placeholder("Call graph\n\nOpen the Call Graph tab to render the program call graph.");
    }
    if (active_page == annotations_page_) {
        populate_annotations_view();
    }
    if (active_page == coverage_page_) {
        populate_coverage_view();
    }
    if (active_page == versions_page_) {
        populate_versions_view();
    }
    if (active_page == hex_view_) {
        load_hex_view();
    }

    if (previously_selected.has_value()) {
        const auto selected_entry = *previously_selected;
        QTimer::singleShot(0, this, [this, selected_entry]() {
            if (!select_function_entry(selected_entry, false) && functions_list_->count() > 0) {
                functions_list_->setCurrentRow(0);
            }
        });
        return;
    }
    if (functions_list_->count() > 0) {
        QTimer::singleShot(0, this, [this]() {
            if (!active_function_entry_.has_value() && functions_list_->count() > 0) {
                functions_list_->setCurrentRow(0);
            }
        });
    }
}

void MainWindow::reset_function_views() {
    active_function_entry_.reset();
    active_function_details_.reset();
    highlighted_cfg_source_block_.reset();
    highlighted_cfg_target_block_.reset();
    summary_view_->setPlainText("Function summary\n\nSelect a function to inspect persisted analysis.");
    disassembly_view_->setPlainText("Disassembly\n\nSelect a function to inspect instructions.");
    decompiler_view_->setPlainText("Decompiler\n\nSelect a function to inspect persisted pseudocode.");
    cfg_graph_view_->show_placeholder("CFG\n\nSelect a function to inspect its control-flow graph.");
    if (workspace_tabs_ != nullptr && workspace_tabs_->currentWidget() == annotations_page_) {
        populate_annotations_view();
    }
    if (workspace_tabs_ != nullptr && workspace_tabs_->currentWidget() == coverage_page_) {
        populate_coverage_view();
    }
    if (workspace_tabs_ != nullptr && workspace_tabs_->currentWidget() == versions_page_) {
        populate_versions_view();
    }
    if (workspace_tabs_ != nullptr && workspace_tabs_->currentWidget() == hex_view_) {
        load_hex_view();
    } else {
        hex_view_->setPlainText("Hex view\n\nOpen the Hex tab to inspect raw bytes.");
    }
}

void MainWindow::populate_function_auxiliary_views(std::uint64_t entry_address) {
    if (controller_ == nullptr) {
        return;
    }

    std::string error;
    const std::optional<persistence::FunctionDetails> details = controller_->load_function(entry_address, error);
    if (!details.has_value()) {
        show_error("Function Load Failed", tr("Failed to load function details.\n\n%1").arg(to_qstring(error)));
        return;
    }

    active_function_entry_ = entry_address;
    active_function_details_ = details;
    if (!suppress_history_) {
        record_navigation(entry_address);
    }

    std::ostringstream summary;
    summary << "Function summary\n\n";
    summary << "Name: " << details->summary.name << "\n";
    summary << "Entry: " << app::WorkspaceController::format_address(details->summary.entry_address) << "\n";
    summary << "Section: " << details->summary.section_name << "\n";
    summary << "Blocks: " << details->summary.block_count << "\n";
    summary << "Instructions: " << details->summary.instruction_count << "\n\n";
    if (details->summary.analysis_summary.empty()) {
        summary << "No persisted analysis summary was stored for this function.\n";
    } else {
        summary << details->summary.analysis_summary << "\n";
    }
    summary_view_->setPlainText(QString::fromStdString(summary.str()));

    std::ostringstream disassembly;
    disassembly << "Function: " << details->summary.name << "\n";
    disassembly << "Entry:    " << app::WorkspaceController::format_address(details->summary.entry_address) << "\n";
    disassembly << "Section:  " << details->summary.section_name << "\n\n";
    for (const auto& block : details->blocks) {
        disassembly << "block " << app::WorkspaceController::format_address(block.start_address) << " -> "
                    << app::WorkspaceController::format_address(block.end_address)
                    << "  successors=" << app::WorkspaceController::format_successors(block.successors) << "\n";
        for (const auto& instruction : details->instructions) {
            if (instruction.block_start != block.start_address) {
                continue;
            }
            disassembly << "  " << app::WorkspaceController::format_address(instruction.address) << "  "
                        << instruction.mnemonic;
            if (!instruction.operands.empty()) {
                disassembly << ' ' << instruction.operands;
            }
            disassembly << "\n";
        }
        disassembly << "\n";
    }
    disassembly_view_->setPlainText(QString::fromStdString(disassembly.str()));

    if (details->summary.decompiled_pseudocode.empty()) {
        decompiler_view_->setPlainText("No persisted decompiler output was stored for this function.");
    } else {
        decompiler_view_->setPlainText(to_qstring(details->summary.decompiled_pseudocode));
    }

    {
        QSignalBlocker calls_blocker(calls_list_);
        QSignalBlocker xrefs_blocker(xrefs_list_);
        calls_list_->setUpdatesEnabled(false);
        xrefs_list_->setUpdatesEnabled(false);
        calls_list_->clear();
        for (const auto& call : details->outgoing_calls) {
            QString text = QString("out  %1 -> %2")
                               .arg(
                                   to_qstring(app::WorkspaceController::format_address(call.call_site)),
                                   format_call_target(call)
                               );
            auto* item = new QListWidgetItem(text);
            item->setData(RoleKind, "call");
            item->setData(RoleDirection, "out");
            item->setData(RolePrimaryAddress, QVariant::fromValue<qulonglong>(call.call_site));
            item->setData(RoleSecondaryAddress, call.callee_entry.has_value() ? QVariant::fromValue<qulonglong>(*call.callee_entry) : QVariant());
            item->setData(RoleLabel, to_qstring(call.callee_name));
            item->setData(RoleFlag, call.is_import);
            calls_list_->addItem(item);
        }
        for (const auto& call : details->incoming_calls) {
            auto* item = new QListWidgetItem(
                QString("in   %1 @ %2")
                    .arg(
                        to_qstring(app::WorkspaceController::format_address(call.caller_entry)),
                        to_qstring(app::WorkspaceController::format_address(call.call_site))
                    )
            );
            item->setData(RoleKind, "call");
            item->setData(RoleDirection, "in");
            item->setData(RolePrimaryAddress, QVariant::fromValue<qulonglong>(call.caller_entry));
            item->setData(RoleSecondaryAddress, QVariant::fromValue<qulonglong>(call.call_site));
            calls_list_->addItem(item);
        }

        xrefs_list_->clear();
        for (const auto& xref : details->xrefs) {
            QString line = QString("%1 -> %2  %3")
                               .arg(
                                   to_qstring(app::WorkspaceController::format_address(xref.from_address)),
                                   to_qstring(app::WorkspaceController::format_address(xref.to_address)),
                                   to_qstring(xref.kind)
                               );
            if (!xref.label.empty()) {
                line += "  " + to_qstring(xref.label);
            }
            auto* item = new QListWidgetItem(line);
            item->setData(RoleKind, "xref");
            item->setData(RoleDirection, to_qstring(xref.kind));
            item->setData(RolePrimaryAddress, QVariant::fromValue<qulonglong>(xref.from_address));
            item->setData(RoleSecondaryAddress, QVariant::fromValue<qulonglong>(xref.to_address));
            item->setData(RoleLabel, to_qstring(xref.label));
            xrefs_list_->addItem(item);
        }
        calls_list_->setUpdatesEnabled(true);
        xrefs_list_->setUpdatesEnabled(true);
    }

    if (workspace_tabs_->currentWidget() == call_graph_view_) {
        render_call_graph();
    }
    if (workspace_tabs_->currentWidget() == cfg_graph_view_) {
        render_cfg_graph();
    }
    if (workspace_tabs_->currentWidget() == annotations_page_) {
        populate_annotations_view();
    }
    if (workspace_tabs_->currentWidget() == coverage_page_) {
        populate_coverage_view();
    }
    if (workspace_tabs_->currentWidget() == versions_page_) {
        populate_versions_view();
    }
    if (workspace_tabs_->currentWidget() == hex_view_) {
        load_hex_view(entry_address);
    }
    persist_session_state();
}

void MainWindow::populate_imports_view() {
    QSignalBlocker blocker(imports_list_);
    imports_list_->setUpdatesEnabled(false);
    imports_list_->clear();
    import_row_by_address_.clear();
    import_row_by_label_.clear();
    if (controller_ == nullptr || controller_->workspace() == nullptr) {
        imports_list_->setUpdatesEnabled(true);
        return;
    }
    const auto& imports = controller_->workspace()->imports;
    for (std::size_t index = 0; index < imports.size(); ++index) {
        const auto& record = imports[index];
        auto* item = new QListWidgetItem(format_import_label(record));
        item->setData(RoleKind, "import");
        item->setData(RolePrimaryAddress, QVariant::fromValue<qulonglong>(record.address));
        item->setData(RoleLabel, record.library_name.empty() ? to_qstring(record.name) : to_qstring(record.library_name + "!" + record.name));
        imports_list_->addItem(item);
        import_row_by_address_[record.address] = static_cast<int>(index);
        const std::string label = record.library_name.empty() ? record.name : record.library_name + "!" + record.name;
        import_row_by_label_[label] = static_cast<int>(index);
    }
    imports_list_->setUpdatesEnabled(true);
}

void MainWindow::populate_exports_view() {
    QSignalBlocker blocker(exports_list_);
    exports_list_->setUpdatesEnabled(false);
    exports_list_->clear();
    export_row_by_address_.clear();
    if (controller_ == nullptr || controller_->workspace() == nullptr) {
        exports_list_->setUpdatesEnabled(true);
        return;
    }
    const auto& exports = controller_->workspace()->exports;
    for (std::size_t index = 0; index < exports.size(); ++index) {
        const auto& record = exports[index];
        auto* item = new QListWidgetItem(
            QString("%1  %2  size=%3")
                .arg(
                    to_qstring(app::WorkspaceController::format_address(record.address)),
                    to_qstring(record.name),
                    QString::number(record.size)
                )
        );
        item->setData(RoleKind, "export");
        item->setData(RolePrimaryAddress, QVariant::fromValue<qulonglong>(record.address));
        exports_list_->addItem(item);
        export_row_by_address_[record.address] = static_cast<int>(index);
    }
    exports_list_->setUpdatesEnabled(true);
}

void MainWindow::populate_strings_view() {
    QSignalBlocker blocker(strings_list_);
    strings_list_->setUpdatesEnabled(false);
    strings_list_->clear();
    string_row_by_address_.clear();
    if (controller_ == nullptr || controller_->workspace() == nullptr) {
        strings_list_->setUpdatesEnabled(true);
        return;
    }
    const auto& strings = controller_->workspace()->strings;
    for (std::size_t index = 0; index < strings.size(); ++index) {
        const auto& record = strings[index];
        auto* item = new QListWidgetItem(
            QString("%1  %2")
                .arg(to_qstring(app::WorkspaceController::format_address(record.address)), to_qstring(record.value))
        );
        item->setData(RoleKind, "string");
        item->setData(RolePrimaryAddress, QVariant::fromValue<qulonglong>(record.address));
        strings_list_->addItem(item);
        string_row_by_address_[record.address] = static_cast<int>(index);
    }
    strings_list_->setUpdatesEnabled(true);
}

void MainWindow::populate_annotations_view() {
    if (comments_table_ == nullptr || types_table_ == nullptr) {
        return;
    }

    comments_table_->setUpdatesEnabled(false);
    types_table_->setUpdatesEnabled(false);
    comments_table_->setRowCount(0);
    types_table_->setRowCount(0);
    if (controller_ == nullptr || controller_->workspace() == nullptr) {
        comments_table_->setUpdatesEnabled(true);
        types_table_->setUpdatesEnabled(true);
        return;
    }

    const auto& workspace = *controller_->workspace();
    int comment_row = 0;
    for (const auto& comment : workspace.comments) {
        const bool visible =
            !active_function_entry_.has_value() ||
            (comment.function_entry.has_value() && *comment.function_entry == *active_function_entry_) ||
            find_function_containing_address(comment.address) == active_function_entry_;
        if (!visible) {
            continue;
        }

        comments_table_->insertRow(comment_row);
        auto* address_item = new QTableWidgetItem(to_qstring(app::WorkspaceController::format_address(comment.address)));
        address_item->setData(Qt::UserRole, comment.id);
        comments_table_->setItem(comment_row, 0, address_item);
        comments_table_->setItem(comment_row, 1, new QTableWidgetItem(to_qstring(comment.scope)));
        comments_table_->setItem(comment_row, 2, new QTableWidgetItem(to_qstring(comment.updated_at)));
        comments_table_->setItem(comment_row, 3, new QTableWidgetItem(preview_text(comment.body)));
        ++comment_row;
    }
    comments_table_->resizeColumnsToContents();

    int type_row = 0;
    for (const auto& annotation : workspace.type_annotations) {
        const bool visible =
            !active_function_entry_.has_value() ||
            !annotation.function_entry.has_value() ||
            *annotation.function_entry == *active_function_entry_;
        if (!visible) {
            continue;
        }

        types_table_->insertRow(type_row);
        auto* symbol_item = new QTableWidgetItem(to_qstring(annotation.symbol_name));
        symbol_item->setData(Qt::UserRole, annotation.id);
        types_table_->setItem(type_row, 0, symbol_item);
        types_table_->setItem(type_row, 1, new QTableWidgetItem(to_qstring(annotation.target_kind)));
        types_table_->setItem(type_row, 2, new QTableWidgetItem(to_qstring(annotation.type_name)));
        types_table_->setItem(type_row, 3, new QTableWidgetItem(to_qstring(annotation.updated_at)));
        types_table_->setItem(type_row, 4, new QTableWidgetItem(preview_text(annotation.note)));
        ++type_row;
    }
    types_table_->resizeColumnsToContents();
    comments_table_->setUpdatesEnabled(true);
    types_table_->setUpdatesEnabled(true);
}

void MainWindow::populate_coverage_view() {
    if (coverage_summary_view_ == nullptr || coverage_table_ == nullptr) {
        return;
    }

    coverage_table_->setUpdatesEnabled(false);
    coverage_table_->setRowCount(0);
    if (controller_ == nullptr || controller_->workspace() == nullptr || !controller_->workspace()->coverage.has_value()) {
        coverage_summary_view_->setPlainText("Coverage view\n\nImport a trace file to visualize execution density.");
        coverage_table_->setUpdatesEnabled(true);
        return;
    }

    const auto& coverage = *controller_->workspace()->coverage;
    std::ostringstream summary;
    summary << "Coverage import\n\n";
    summary << "Input: " << (coverage.input_label.empty() ? "<unnamed>" : coverage.input_label) << "\n";
    summary << "Imported: " << coverage.imported_at << "\n";
    summary << "Crash: " << (coverage.crash_address.has_value()
                                    ? app::WorkspaceController::format_address(*coverage.crash_address)
                                    : std::string("-"))
            << "\n";
    summary << "Summary: " << coverage.crash_summary << "\n";
    if (!coverage.crash_hints.empty()) {
        summary << "\nCrash hints\n" << coverage.crash_hints << "\n";
    }
    if (!coverage.mutation_hooks.empty()) {
        summary << "\nMutation hooks\n" << coverage.mutation_hooks << "\n";
    }
    if (!coverage.harness_bundle.empty()) {
        summary << "\nHarness bundle\n" << coverage.harness_bundle << "\n";
    }
    coverage_summary_view_->setPlainText(QString::fromStdString(summary.str()));

    for (int row = 0; row < static_cast<int>(coverage.functions.size()); ++row) {
        const auto& function = coverage.functions[static_cast<std::size_t>(row)];
        coverage_table_->insertRow(row);
        auto* function_item = new QTableWidgetItem(to_qstring(function.function_name));
        function_item->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(function.function_entry));
        coverage_table_->setItem(row, 0, function_item);
        coverage_table_->setItem(row, 1, new QTableWidgetItem(to_qstring(app::WorkspaceController::format_address(function.function_entry))));
        coverage_table_->setItem(row, 2, new QTableWidgetItem(QString::number(static_cast<qulonglong>(function.hit_count))));
        coverage_table_->setItem(row, 3, new QTableWidgetItem(QString::number(static_cast<qulonglong>(function.instruction_count))));
        coverage_table_->setItem(row, 4, new QTableWidgetItem(QString::number(function.coverage_ratio * 100.0, 'f', 1) + "%"));
        coverage_table_->setItem(row, 5, new QTableWidgetItem(function.contains_crash_address ? tr("yes") : tr("no")));
    }
    coverage_table_->resizeColumnsToContents();
    coverage_table_->setUpdatesEnabled(true);
}

void MainWindow::populate_versions_view() {
    if (versions_table_ == nullptr) {
        return;
    }

    versions_table_->setUpdatesEnabled(false);
    versions_table_->setRowCount(0);
    if (controller_ == nullptr || controller_->workspace() == nullptr) {
        versions_table_->setUpdatesEnabled(true);
        return;
    }

    const auto& versions = controller_->workspace()->versions;
    for (int row = 0; row < static_cast<int>(versions.size()); ++row) {
        const auto& version = versions[static_cast<std::size_t>(row)];
        versions_table_->insertRow(row);
        versions_table_->setItem(row, 0, new QTableWidgetItem(to_qstring(version.created_at)));
        versions_table_->setItem(row, 1, new QTableWidgetItem(to_qstring(version.kind)));
        versions_table_->setItem(row, 2, new QTableWidgetItem(to_qstring(version.title)));
        versions_table_->setItem(row, 3, new QTableWidgetItem(preview_text(version.detail, 120)));
    }
    versions_table_->resizeColumnsToContents();
    versions_table_->setUpdatesEnabled(true);
}

void MainWindow::render_call_graph() {
    if (controller_ == nullptr || controller_->workspace() == nullptr) {
        call_graph_view_->show_placeholder();
        return;
    }

    const auto& workspace = *controller_->workspace();
    if (workspace.functions.empty()) {
        call_graph_view_->show_placeholder("Call graph\n\nNo discovered functions were persisted for this run.");
        return;
    }

    std::optional<std::uint64_t> selected = active_function_entry_;
    std::vector<persistence::FunctionSummary> prioritized = workspace.functions;
    if (selected.has_value()) {
        std::sort(
            prioritized.begin(),
            prioritized.end(),
            [&](const auto& left, const auto& right) {
                return std::pair(left.entry_address != *selected, left.entry_address) <
                       std::pair(right.entry_address != *selected, right.entry_address);
            }
        );
    }

    const std::size_t max_nodes = 20;
    prioritized.resize(std::min<std::size_t>(prioritized.size(), max_nodes));
    std::map<std::uint64_t, int> layer_by_entry;
    std::map<std::uint64_t, int> indegree;
    std::map<std::uint64_t, std::vector<std::uint64_t>> adjacency;
    std::vector<GraphNode> nodes;
    std::vector<GraphEdge> edges;
    std::map<QString, bool> function_ids;

    for (const auto& function : prioritized) {
        indegree[function.entry_address] = 0;
    }

    for (const auto& call : workspace.call_edges) {
        if (call.is_import || !call.callee_entry.has_value()) {
            continue;
        }
        if (!indegree.contains(call.caller_entry) || !indegree.contains(*call.callee_entry)) {
            continue;
        }
        adjacency[call.caller_entry].push_back(*call.callee_entry);
        indegree[*call.callee_entry] += 1;
    }

    std::deque<std::uint64_t> queue;
    if (selected.has_value() && indegree.contains(*selected)) {
        layer_by_entry[*selected] = 0;
        queue.push_back(*selected);
    } else if (!indegree.empty()) {
        const auto root = std::min_element(
            indegree.begin(),
            indegree.end(),
            [](const auto& left, const auto& right) {
                return std::tie(left.second, left.first) < std::tie(right.second, right.first);
            }
        );
        layer_by_entry[root->first] = 0;
        queue.push_back(root->first);
    }

    while (!queue.empty()) {
        const auto current = queue.front();
        queue.pop_front();
        for (const auto callee : adjacency[current]) {
            if (layer_by_entry.contains(callee)) {
                continue;
            }
            layer_by_entry[callee] = layer_by_entry[current] + 1;
            queue.push_back(callee);
        }
    }

    int next_layer = layer_by_entry.empty() ? 0 : (layer_by_entry.rbegin()->second + 1);
    int overflow_index = 0;
    constexpr int overflow_bucket_size = 4;
    for (const auto& function : prioritized) {
        if (!layer_by_entry.contains(function.entry_address)) {
            layer_by_entry[function.entry_address] = next_layer + (overflow_index / overflow_bucket_size);
            ++overflow_index;
        }
    }
    const int import_layer =
        next_layer + (overflow_index == 0 ? 0 : ((overflow_index + overflow_bucket_size - 1) / overflow_bucket_size));

    std::map<int, int> layer_positions;
    for (const auto& function : prioritized) {
        const int layer = layer_by_entry[function.entry_address];
        const int order = layer_positions[layer]++;
        const bool is_selected = selected.has_value() && function.entry_address == *selected;
        const bool is_highlighted =
            (highlighted_call_source_.has_value() && function.entry_address == *highlighted_call_source_) ||
            (highlighted_call_target_.has_value() && function.entry_address == *highlighted_call_target_);
        nodes.push_back(
            GraphNode{
                .id = to_qstring(std::to_string(function.entry_address)),
                .label = to_qstring(function.name),
                .detail = QString("%1\nblocks=%2 instrs=%3")
                              .arg(to_qstring(app::WorkspaceController::format_address(function.entry_address)))
                              .arg(function.block_count)
                              .arg(function.instruction_count),
                .fill = is_highlighted ? QColor("#F4DEC9") : (is_selected ? QColor("#BCD4C8") : QColor("#DCE6D8")),
                .border = is_highlighted ? QColor("#9C6644") : (is_selected ? QColor("#183A37") : QColor("#345E5A")),
                .detail_color = is_highlighted ? QColor("#7F5539") : QColor("#385F5A"),
                .border_width = is_highlighted ? 2.8 : (is_selected ? 2.2 : 1.4),
                .layer = layer,
                .order = order,
            }
        );
        function_ids[to_qstring(std::to_string(function.entry_address))] = true;
    }

    std::map<QString, int> import_orders;
    for (const auto& call : workspace.call_edges) {
        const QString caller_id = to_qstring(std::to_string(call.caller_entry));
        if (!function_ids.contains(caller_id)) {
            continue;
        }
        if (call.is_import) {
            const QString import_id = "import:" + to_qstring(call.callee_name);
            if (!import_orders.contains(import_id) && import_orders.size() < 8) {
                import_orders[import_id] = static_cast<int>(import_orders.size());
                const bool is_highlighted =
                    highlighted_call_source_.has_value() && call.caller_entry == *highlighted_call_source_ &&
                    highlighted_import_target_ == to_qstring(call.callee_name);
                nodes.push_back(
                    GraphNode{
                        .id = import_id,
                        .label = to_qstring(call.callee_name),
                        .detail = "import target",
                        .fill = is_highlighted ? QColor("#F7C59F") : QColor("#F4DEC9"),
                        .border = is_highlighted ? QColor("#8C4F2F") : QColor("#9C6644"),
                        .detail_color = QColor("#7F5539"),
                        .border_width = is_highlighted ? 2.8 : 1.4,
                        .layer = import_layer,
                        .order = import_orders[import_id],
                    }
                );
            }
            if (import_orders.contains(import_id)) {
                const bool is_highlighted =
                    highlighted_call_source_.has_value() && call.caller_entry == *highlighted_call_source_ &&
                    highlighted_import_target_ == to_qstring(call.callee_name);
                edges.push_back(
                    GraphEdge{
                        .source = caller_id,
                        .target = import_id,
                        .color = is_highlighted ? QColor("#D97706") : QColor("#B26D3B"),
                        .width = is_highlighted ? 3.4 : (selected.has_value() && call.caller_entry == *selected ? 3.0 : 2.0),
                        .style = Qt::DashLine,
                        .route_index = static_cast<int>(edges.size() % 3),
                        .label = "import",
                    }
                );
            }
            continue;
        }
        if (!call.callee_entry.has_value()) {
            continue;
        }
        const QString callee_id = to_qstring(std::to_string(*call.callee_entry));
        if (!function_ids.contains(callee_id)) {
            continue;
        }
        edges.push_back(
            GraphEdge{
                .source = caller_id,
                .target = callee_id,
                .color = (highlighted_call_source_.has_value() && highlighted_call_target_.has_value() &&
                          call.caller_entry == *highlighted_call_source_ && *call.callee_entry == *highlighted_call_target_)
                             ? QColor("#D97706")
                             : (selected.has_value() && *call.callee_entry == *selected ? QColor("#0F766E") : QColor("#3B7A57")),
                .width = (highlighted_call_source_.has_value() && highlighted_call_target_.has_value() &&
                          call.caller_entry == *highlighted_call_source_ && *call.callee_entry == *highlighted_call_target_)
                             ? 3.4
                             : ((selected.has_value() && (call.caller_entry == *selected || *call.callee_entry == *selected)) ? 2.8
                                                                                                                              : 2.0),
                .style = Qt::SolidLine,
                .route_index = static_cast<int>(edges.size() % 3),
                .label = QString(),
            }
        );
    }

    call_graph_view_->render_graph("Whole-program call graph", nodes, edges);
}

void MainWindow::render_cfg_graph() {
    if (!active_function_details_.has_value()) {
        cfg_graph_view_->show_placeholder("CFG\n\nSelect a function to inspect its control-flow graph.");
        return;
    }

    const auto& details = *active_function_details_;
    if (details.blocks.empty()) {
        cfg_graph_view_->show_placeholder("CFG\n\nNo basic blocks were persisted for this function.");
        return;
    }

    std::map<std::uint64_t, persistence::BasicBlockRecord> block_map;
    std::map<std::uint64_t, int> layer_by_block;
    std::map<std::uint64_t, std::vector<std::uint64_t>> successor_map;
    for (const auto& block : details.blocks) {
        block_map[block.start_address] = block;
    }
    for (const auto& block : details.blocks) {
        auto& successors = successor_map[block.start_address];
        for (const auto successor : block.successors) {
            if (block_map.contains(successor)) {
                successors.push_back(successor);
            }
        }
    }

    const std::uint64_t entry = details.blocks.front().start_address;
    std::deque<std::uint64_t> queue{entry};
    layer_by_block[entry] = 0;
    while (!queue.empty()) {
        const auto current = queue.front();
        queue.pop_front();
        for (const auto successor : successor_map[current]) {
            if (layer_by_block.contains(successor)) {
                continue;
            }
            layer_by_block[successor] = layer_by_block[current] + 1;
            queue.push_back(successor);
        }
    }

    int next_layer = layer_by_block.empty() ? 0 : (layer_by_block.rbegin()->second + 1);
    for (const auto& block : details.blocks) {
        if (!layer_by_block.contains(block.start_address)) {
            layer_by_block[block.start_address] = next_layer++;
        }
    }

    std::map<int, int> layer_positions;
    std::vector<GraphNode> nodes;
    std::vector<GraphEdge> edges;
    const std::optional<std::uint64_t> runtime_block =
        debug_snapshot_.has_value() && debug_snapshot_->location.has_value() &&
                debug_snapshot_->location->function_entry == details.summary.entry_address
            ? std::optional<std::uint64_t>(debug_snapshot_->location->block_start)
            : std::nullopt;
    for (const auto& block : details.blocks) {
        const int layer = layer_by_block[block.start_address];
        const int order = layer_positions[layer]++;
        const bool is_entry = block.start_address == entry;
        const bool is_runtime = runtime_block.has_value() && block.start_address == *runtime_block;
        const bool is_flow_source = highlighted_cfg_source_block_.has_value() && block.start_address == *highlighted_cfg_source_block_;
        const bool is_flow_target = highlighted_cfg_target_block_.has_value() && block.start_address == *highlighted_cfg_target_block_;
        nodes.push_back(
            GraphNode{
                .id = to_qstring(app::WorkspaceController::format_address(block.start_address)),
                .label = to_qstring(app::WorkspaceController::format_address(block.start_address)),
                .detail = QString("%1\n%2 exits")
                              .arg(to_qstring(app::WorkspaceController::format_address(block.end_address)))
                              .arg(static_cast<int>(successor_map[block.start_address].size())),
                .fill = (is_flow_source || is_flow_target)
                            ? QColor("#F7C59F")
                            : (is_runtime ? QColor("#F4DEC9") : (is_entry ? QColor("#CFE1D3") : QColor("#DDE9D7"))),
                .border = (is_flow_source || is_flow_target)
                              ? QColor("#8C4F2F")
                              : (is_runtime ? QColor("#9C6644") : (is_entry ? QColor("#183A37") : QColor("#345E5A"))),
                .detail_color = (is_flow_source || is_flow_target)
                                    ? QColor("#7F5539")
                                    : (is_runtime ? QColor("#7F5539") : QColor("#385F5A")),
                .border_width = (is_flow_source || is_flow_target) ? 2.8 : (is_runtime ? 2.4 : (is_entry ? 2.0 : 1.4)),
                .layer = layer,
                .order = order,
            }
        );

        const auto& successors = successor_map[block.start_address];
        for (std::size_t index = 0; index < successors.size(); ++index) {
            const bool is_highlighted =
                highlighted_cfg_source_block_.has_value() && highlighted_cfg_target_block_.has_value() &&
                block.start_address == *highlighted_cfg_source_block_ && successors[index] == *highlighted_cfg_target_block_;
            GraphEdge edge{
                .source = to_qstring(app::WorkspaceController::format_address(block.start_address)),
                .target = to_qstring(app::WorkspaceController::format_address(successors[index])),
                .color = is_highlighted
                             ? QColor("#D97706")
                             : (successors[index] < block.start_address
                                    ? QColor("#C44536")
                                    : (successors.size() > 1 ? (index == 0 ? QColor("#2C7DA0") : QColor("#B26D3B"))
                                                             : QColor("#52796F"))),
                .width = is_highlighted ? 3.4 : 2.0,
                .style = successors[index] < block.start_address ? Qt::DashLine : Qt::SolidLine,
                .route_index = static_cast<int>(index),
                .label = is_highlighted ? "flow" : (successors[index] < block.start_address ? "loop" : QString()),
            };
            edges.push_back(std::move(edge));
        }
    }

    cfg_graph_view_->render_graph("CFG: " + to_qstring(details.summary.name), nodes, edges);
}

void MainWindow::load_hex_view(const std::optional<std::uint64_t> highlight_address) {
    if (current_binary_path_.empty() || !std::filesystem::exists(current_binary_path_)) {
        hex_view_->setPlainText("Hex view unavailable.\n\nOpen a binary or project to inspect raw bytes.");
        return;
    }

    std::ifstream stream(current_binary_path_, std::ios::binary);
    if (!stream) {
        hex_view_->setPlainText("Hex view unavailable.\n\nFailed to open the current binary.");
        return;
    }

    constexpr std::size_t window_size = 1024;
    std::uint64_t read_offset = 0;
    if (highlight_address.has_value() && live_program_.has_value()) {
        for (const auto& section : live_program_->image.sections()) {
            const auto section_begin = section.virtual_address;
            const auto section_end = section.virtual_address + section.bytes.size();
            if (*highlight_address >= section_begin && *highlight_address < section_end) {
                const auto section_offset = *highlight_address - section_begin;
                const auto centered_offset = section.file_offset + (section_offset > 128 ? section_offset - 128 : 0);
                read_offset = centered_offset;
                break;
            }
        }
    }

    stream.seekg(static_cast<std::streamoff>(read_offset), std::ios::beg);
    std::vector<unsigned char> bytes(window_size);
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    bytes.resize(static_cast<std::size_t>(stream.gcount()));

    std::ostringstream output;
    if (highlight_address.has_value()) {
        output << "Selected function entry: " << app::WorkspaceController::format_address(*highlight_address) << "\n\n";
    }
    for (std::size_t offset = 0; offset < bytes.size(); offset += 16) {
        output << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << (read_offset + offset) << "  ";
        std::string ascii;
        for (std::size_t index = 0; index < 16; ++index) {
            if (offset + index < bytes.size()) {
                const auto byte = bytes[offset + index];
                output << std::setw(2) << static_cast<unsigned int>(byte) << ' ';
                ascii.push_back(byte >= 32 && byte < 127 ? static_cast<char>(byte) : '.');
            } else {
                output << "   ";
                ascii.push_back(' ');
            }
        }
        output << ' ' << ascii << '\n';
    }

    hex_view_->setPlainText(QString::fromStdString(output.str()));
}

void MainWindow::update_navigation_actions() {
    back_action_->setEnabled(navigation_index_ > 0);
    forward_action_->setEnabled(navigation_index_ >= 0 && navigation_index_ + 1 < static_cast<int>(navigation_history_.size()));
}

void MainWindow::set_analysis_busy(const bool busy) {
    open_binary_action_->setEnabled(!busy);
    open_project_action_->setEnabled(!busy);
    refresh_action_->setEnabled(!busy);
    start_debugger_action_->setEnabled(!busy && !debug_session_);
    if (import_coverage_action_ != nullptr) {
        import_coverage_action_->setEnabled(!busy);
    }
}

void MainWindow::set_debugger_running(const bool running) {
    start_debugger_action_->setEnabled(!running && analysis_future_ == nullptr);
    stop_debugger_action_->setEnabled(running);
    if (continue_button_ != nullptr) {
        continue_button_->setEnabled(running);
    }
    if (step_button_ != nullptr) {
        step_button_->setEnabled(running);
    }
    if (add_breakpoint_button_ != nullptr) {
        add_breakpoint_button_->setEnabled(running);
    }
    if (remove_breakpoint_button_ != nullptr) {
        remove_breakpoint_button_->setEnabled(running);
    }
    if (refresh_memory_button_ != nullptr) {
        refresh_memory_button_->setEnabled(running);
    }
    if (apply_patch_button_ != nullptr) {
        apply_patch_button_->setEnabled(running);
    }
    if (breakpoint_address_edit_ != nullptr) {
        breakpoint_address_edit_->setEnabled(running);
    }
    if (memory_address_edit_ != nullptr) {
        memory_address_edit_->setEnabled(running);
    }
    if (memory_length_edit_ != nullptr) {
        memory_length_edit_->setEnabled(running);
    }
    if (patch_bytes_edit_ != nullptr) {
        patch_bytes_edit_->setEnabled(running);
    }
    if (watch_expression_edit_ != nullptr) {
        watch_expression_edit_->setEnabled(true);
    }
    if (add_watch_button_ != nullptr) {
        add_watch_button_->setEnabled(true);
    }
    if (remove_watch_button_ != nullptr) {
        remove_watch_button_->setEnabled(!watch_expressions_.empty());
    }
    if (live_patch_action_ != nullptr) {
        live_patch_action_->setEnabled(running);
    }
    if (debugger_status_label_ != nullptr) {
        debugger_status_label_->setText(running ? tr("Session: active") : tr("Session: idle"));
    }
}

void MainWindow::append_log(QPlainTextEdit* view, const QString& text) const {
    if (view == nullptr || text.trimmed().isEmpty()) {
        return;
    }
    view->appendPlainText(text.trimmed());
}

void MainWindow::record_navigation(const std::uint64_t entry_address) {
    if (navigation_index_ >= 0 && navigation_index_ < static_cast<int>(navigation_history_.size()) &&
        navigation_history_[navigation_index_] == entry_address) {
        return;
    }
    navigation_history_.resize(static_cast<std::size_t>(navigation_index_ + 1));
    navigation_history_.push_back(entry_address);
    navigation_index_ = static_cast<int>(navigation_history_.size()) - 1;
    update_navigation_actions();
}

bool MainWindow::select_function_entry(const std::uint64_t entry_address, const bool record_history) {
    const auto it = function_row_by_entry_.find(entry_address);
    if (it == function_row_by_entry_.end()) {
        return false;
    }
    suppress_history_ = !record_history;
    functions_list_->setCurrentRow(it->second);
    suppress_history_ = false;
    functions_list_->setFocus();
    return true;
}

std::optional<std::uint64_t> MainWindow::find_function_containing_address(const std::uint64_t address) const {
    for (const auto& [start, end, entry] : function_ranges_) {
        if (start <= address && address <= end) {
            return entry;
        }
    }
    return std::nullopt;
}

void MainWindow::select_list_row(QListWidget* widget, const int row) {
    if (widget == nullptr || row < 0 || row >= widget->count()) {
        return;
    }
    widget->setCurrentRow(row);
    widget->scrollToItem(widget->item(row));
}

void MainWindow::clear_flow_highlights() {
    highlighted_call_source_.reset();
    highlighted_call_target_.reset();
    highlighted_import_target_.clear();
    highlighted_cfg_source_block_.reset();
    highlighted_cfg_target_block_.reset();
}

std::optional<std::uint64_t> MainWindow::block_start_for_address(const std::uint64_t address) const {
    if (!active_function_details_.has_value()) {
        return std::nullopt;
    }

    for (const auto& block : active_function_details_->blocks) {
        if (block.start_address <= address && address <= block.end_address) {
            return block.start_address;
        }
    }
    return std::nullopt;
}

bool MainWindow::ensure_live_program_loaded(std::string& out_error) {
    out_error.clear();
    if (live_program_.has_value()) {
        return true;
    }
    if (current_binary_path_.empty()) {
        out_error = "No binary is loaded.";
        return false;
    }
    return app::AnalysisRunner::load_program(current_binary_path_, live_program_.emplace(), out_error);
}

bool MainWindow::refresh_debug_snapshot(const debugger::StopEvent& stop, const bool show_errors) {
    if (is_terminal_stop(stop.reason)) {
        append_log(debugger_output_view_, stop_summary(stop));
        append_log(output_view_, "[debugger] " + stop_summary(stop));
        debug_snapshot_.reset();
        previous_registers_.reset();
        clear_debugger_views();
        debug_session_.reset();
        breakpoint_addresses_.clear();
        set_debugger_running(false);
        return true;
    }

    if (!debug_session_ || !live_program_.has_value()) {
        return false;
    }

    if (debug_snapshot_.has_value()) {
        previous_registers_ = debug_snapshot_->registers;
    }

    std::string error;
    debugger::RuntimeSnapshot snapshot;
    if (!debugger::capture_runtime_snapshot(*debug_session_, live_program_->image, live_program_->analysis, stop, snapshot, error)) {
        if (show_errors) {
            show_error("Debugger Refresh Failed", tr("Failed to capture runtime snapshot.\n\n%1").arg(to_qstring(error)));
        }
        append_log(output_view_, "[debugger] snapshot failed: " + to_qstring(error));
        return false;
    }

    debug_snapshot_ = snapshot;
    populate_registers_view(snapshot.registers);
    populate_stack_view(snapshot.registers);
    populate_call_stack_view(snapshot.registers);
    populate_breakpoints_view();
    populate_threads_view();
    populate_watch_view();

    if (memory_address_edit_->text().trimmed().isEmpty()) {
        memory_address_edit_->setText(to_qstring(app::WorkspaceController::format_address(snapshot.registers.rip)));
    }
    refresh_memory_pane();

    QString log_line = stop_summary(snapshot.stop);
    if (snapshot.stop.thread_id > 0) {
        log_line += tr("\nthread %1").arg(snapshot.stop.thread_id);
    }
    if (snapshot.location.has_value()) {
        log_line += tr("\n%1 @ %2")
                        .arg(
                            to_qstring(snapshot.location->function_name),
                            to_qstring(app::WorkspaceController::format_address(snapshot.location->instruction_address))
                        );
    }
    append_log(debugger_output_view_, log_line);
    append_log(output_view_, "[debugger] " + stop_summary(snapshot.stop));
    if (debugger_status_label_ != nullptr) {
        debugger_status_label_->setText(
            tr("Session: active  |  %1")
                .arg(stop_summary(snapshot.stop).split('\n').front())
        );
    }

    if (snapshot.location.has_value() && snapshot.location->function_entry != 0U) {
        select_function_entry(snapshot.location->function_entry);
        workspace_tabs_->setCurrentWidget(summary_view_);
    }
    workspace_tabs_->setCurrentWidget(debugger_page_);
    return true;
}

void MainWindow::populate_registers_view(const debugger::RegisterState& registers) {
    if (registers_table_ == nullptr) {
        return;
    }

    const std::array<std::pair<const char*, std::uint64_t>, 18> rows = {{
        {"RIP", registers.rip}, {"RSP", registers.rsp}, {"RBP", registers.rbp}, {"RAX", registers.rax},
        {"RBX", registers.rbx}, {"RCX", registers.rcx}, {"RDX", registers.rdx}, {"RSI", registers.rsi},
        {"RDI", registers.rdi}, {"R8", registers.r8},   {"R9", registers.r9},   {"R10", registers.r10},
        {"R11", registers.r11}, {"R12", registers.r12}, {"R13", registers.r13}, {"R14", registers.r14},
        {"R15", registers.r15}, {"EFLAGS", registers.eflags},
    }};

    registers_table_->setRowCount(static_cast<int>(rows.size()));
    for (int row = 0; row < static_cast<int>(rows.size()); ++row) {
        const auto& [name, value] = rows[static_cast<std::size_t>(row)];
        auto* name_item = new QTableWidgetItem(QString::fromLatin1(name));
        auto* value_item = new QTableWidgetItem(to_qstring(app::WorkspaceController::format_address(value)));
        auto* symbol_item = new QTableWidgetItem(format_symbol_label(value));
        const auto changed = previous_registers_.has_value() &&
                             [&]() {
                                 const auto& previous = *previous_registers_;
                                 const std::string_view register_name(name);
                                 if (register_name == "RIP") return previous.rip != value;
                                 if (register_name == "RSP") return previous.rsp != value;
                                 if (register_name == "RBP") return previous.rbp != value;
                                 if (register_name == "RAX") return previous.rax != value;
                                 if (register_name == "RBX") return previous.rbx != value;
                                 if (register_name == "RCX") return previous.rcx != value;
                                 if (register_name == "RDX") return previous.rdx != value;
                                 if (register_name == "RSI") return previous.rsi != value;
                                 if (register_name == "RDI") return previous.rdi != value;
                                 if (register_name == "R8") return previous.r8 != value;
                                 if (register_name == "R9") return previous.r9 != value;
                                 if (register_name == "R10") return previous.r10 != value;
                                 if (register_name == "R11") return previous.r11 != value;
                                 if (register_name == "R12") return previous.r12 != value;
                                 if (register_name == "R13") return previous.r13 != value;
                                 if (register_name == "R14") return previous.r14 != value;
                                 if (register_name == "R15") return previous.r15 != value;
                                 if (register_name == "EFLAGS") return previous.eflags != value;
                                 return false;
                             }();
        if (changed) {
            const QBrush brush(QColor("#E8C7A7"));
            name_item->setBackground(brush);
            value_item->setBackground(brush);
            symbol_item->setBackground(brush);
        }
        registers_table_->setItem(row, 0, name_item);
        registers_table_->setItem(row, 1, value_item);
        registers_table_->setItem(row, 2, symbol_item);
    }
    registers_table_->resizeColumnsToContents();
}

void MainWindow::populate_stack_view(const debugger::RegisterState& registers) {
    if (stack_table_ == nullptr || !debug_session_) {
        return;
    }

    std::string error;
    std::vector<std::byte> bytes;
    if (!debug_session_->read_memory(registers.rsp, 16 * sizeof(std::uint64_t), bytes, error)) {
        stack_table_->setRowCount(1);
        stack_table_->setItem(0, 0, new QTableWidgetItem(to_qstring(app::WorkspaceController::format_address(registers.rsp))));
        stack_table_->setItem(0, 1, new QTableWidgetItem("read failed"));
        stack_table_->setItem(0, 2, new QTableWidgetItem(to_qstring(error)));
        return;
    }

    const int rows = static_cast<int>(bytes.size() / sizeof(std::uint64_t));
    stack_table_->setRowCount(rows);
    for (int row = 0; row < rows; ++row) {
        const auto address = registers.rsp + static_cast<std::uint64_t>(row * sizeof(std::uint64_t));
        const auto value = read_qword(bytes, static_cast<std::size_t>(row * sizeof(std::uint64_t)));
        stack_table_->setItem(row, 0, new QTableWidgetItem(to_qstring(app::WorkspaceController::format_address(address))));
        stack_table_->setItem(row, 1, new QTableWidgetItem(to_qstring(app::WorkspaceController::format_address(value))));
        stack_table_->setItem(row, 2, new QTableWidgetItem(format_symbol_label(value)));
    }
    stack_table_->resizeColumnsToContents();
}

void MainWindow::populate_call_stack_view(const debugger::RegisterState& registers) {
    if (call_stack_table_ == nullptr) {
        return;
    }

    call_stack_table_->setRowCount(0);
    if (!debug_session_ || !live_program_.has_value()) {
        return;
    }

    auto append_frame = [this](const int row, const std::uint64_t instruction, const std::uint64_t stack_value) {
        call_stack_table_->insertRow(row);
        call_stack_table_->setItem(row, 0, new QTableWidgetItem(QString("#%1").arg(row)));
        call_stack_table_->setItem(
            row,
            1,
            new QTableWidgetItem(to_qstring(app::WorkspaceController::format_address(instruction)))
        );

        QString function_label = format_symbol_label(instruction);
        if (function_label.isEmpty()) {
            if (const auto containing = find_function_containing_address(instruction); containing.has_value()) {
                std::string error;
                const auto details = controller_ != nullptr ? controller_->load_function(*containing, error) : std::nullopt;
                if (details.has_value() && error.empty()) {
                    function_label = to_qstring(details->summary.name);
                }
            }
        }
        if (function_label.isEmpty()) {
            function_label = tr("<unknown>");
        }

        call_stack_table_->setItem(row, 2, new QTableWidgetItem(function_label));
        call_stack_table_->setItem(
            row,
            3,
            new QTableWidgetItem(to_qstring(app::WorkspaceController::format_address(stack_value)))
        );
    };

    append_frame(0, registers.rip, registers.rsp);

    if (registers.rbp == 0) {
        call_stack_table_->resizeColumnsToContents();
        return;
    }

    std::uint64_t frame_pointer = registers.rbp;
    for (int row = 1; row < 16; ++row) {
        std::string error;
        std::vector<std::byte> frame_bytes;
        if (!debug_session_->read_memory(frame_pointer, 16, frame_bytes, error) || frame_bytes.size() < 16) {
            break;
        }

        const auto next_frame = read_qword(frame_bytes, 0);
        const auto return_address = read_qword(frame_bytes, 8);
        if (return_address == 0 || next_frame == frame_pointer) {
            break;
        }

        append_frame(row, return_address, frame_pointer);
        if (next_frame <= frame_pointer) {
            break;
        }
        frame_pointer = next_frame;
    }

    call_stack_table_->resizeColumnsToContents();
}

void MainWindow::populate_breakpoints_view() {
    if (breakpoints_table_ == nullptr) {
        return;
    }

    breakpoints_table_->setRowCount(static_cast<int>(breakpoint_addresses_.size()));
    int row = 0;
    for (const auto address : breakpoint_addresses_) {
        breakpoints_table_->setItem(
            row,
            0,
            new QTableWidgetItem(to_qstring(app::WorkspaceController::format_address(address)))
        );
        breakpoints_table_->setItem(row, 1, new QTableWidgetItem(format_symbol_label(address)));
        ++row;
    }
    breakpoints_table_->resizeColumnsToContents();
}

void MainWindow::populate_threads_view() {
    if (threads_table_ == nullptr) {
        return;
    }

    threads_table_->setRowCount(0);
    if (!debug_session_ || !debug_session_->is_active()) {
        return;
    }

    std::vector<debugger::ThreadInfo> threads;
    std::string error;
    if (!debug_session_->list_threads(threads, error)) {
        threads_table_->setRowCount(1);
        threads_table_->setItem(0, 0, new QTableWidgetItem(tr("unavailable")));
        threads_table_->setItem(0, 1, new QTableWidgetItem(to_qstring(error)));
        return;
    }

    for (int row = 0; row < static_cast<int>(threads.size()); ++row) {
        const auto& thread = threads[static_cast<std::size_t>(row)];
        threads_table_->insertRow(row);
        auto* thread_item = new QTableWidgetItem(QString::number(thread.thread_id));
        thread_item->setData(Qt::UserRole, thread.thread_id);
        threads_table_->setItem(row, 0, thread_item);
        threads_table_->setItem(row, 1, new QTableWidgetItem(to_qstring(thread.state)));
        threads_table_->setItem(
            row,
            2,
            new QTableWidgetItem(
                thread.instruction_pointer.has_value()
                    ? to_qstring(app::WorkspaceController::format_address(*thread.instruction_pointer))
                    : QString("-")
            )
        );
        threads_table_->setItem(row, 3, new QTableWidgetItem(thread.selected ? tr("current") : QString()));
    }
    threads_table_->resizeColumnsToContents();
}

void MainWindow::populate_watch_view() {
    if (watch_table_ == nullptr) {
        return;
    }

    watch_table_->setRowCount(0);
    for (int row = 0; row < static_cast<int>(watch_expressions_.size()); ++row) {
        watch_table_->insertRow(row);
        const QString expression = watch_expressions_[static_cast<std::size_t>(row)];
        watch_table_->setItem(row, 0, new QTableWidgetItem(expression));
        watch_table_->setItem(row, 1, new QTableWidgetItem(evaluate_watch_expression(expression)));
        const auto address = parse_runtime_address(expression);
        watch_table_->setItem(
            row,
            2,
            new QTableWidgetItem(address.has_value() ? format_symbol_label(*address) : QString())
        );
    }
    watch_table_->resizeColumnsToContents();
    if (remove_watch_button_ != nullptr) {
        remove_watch_button_->setEnabled(!watch_expressions_.empty());
    }
}

void MainWindow::populate_memory_view(const std::uint64_t address) {
    if (debugger_memory_view_ == nullptr) {
        return;
    }
    if (!debug_session_) {
        debugger_memory_view_->setPlainText("Memory pane unavailable.\n\nStart a debugger session first.");
        return;
    }

    bool ok = false;
    int byte_count = memory_length_edit_ != nullptr ? memory_length_edit_->text().toInt(&ok) : 128;
    if (!ok) {
        byte_count = 128;
    }
    byte_count = std::clamp(byte_count, 16, 1024);
    if (memory_length_edit_ != nullptr) {
        memory_length_edit_->setText(QString::number(byte_count));
    }

    std::string error;
    std::vector<std::byte> bytes;
    if (!debug_session_->read_memory(address, static_cast<std::size_t>(byte_count), bytes, error)) {
        debugger_memory_view_->setPlainText(
            tr("Memory read failed at %1\n\n%2")
                .arg(to_qstring(app::WorkspaceController::format_address(address)), to_qstring(error))
        );
        return;
    }

    QString text = tr("Memory @ %1").arg(to_qstring(app::WorkspaceController::format_address(address)));
    const QString symbol = format_symbol_label(address);
    if (!symbol.isEmpty()) {
        text += "\n" + symbol;
    }
    text += "\n\n" + format_runtime_hex(address, bytes);
    debugger_memory_view_->setPlainText(text);
}

void MainWindow::clear_debugger_views() {
    if (registers_table_ != nullptr) {
        registers_table_->setRowCount(0);
    }
    if (stack_table_ != nullptr) {
        stack_table_->setRowCount(0);
    }
    if (call_stack_table_ != nullptr) {
        call_stack_table_->setRowCount(0);
    }
    if (breakpoints_table_ != nullptr) {
        breakpoints_table_->setRowCount(0);
    }
    if (threads_table_ != nullptr) {
        threads_table_->setRowCount(0);
    }
    if (watch_table_ != nullptr) {
        watch_table_->setRowCount(static_cast<int>(watch_expressions_.size()));
    }
    if (debugger_memory_view_ != nullptr) {
        debugger_memory_view_->setPlainText("Memory pane\n\nLaunch a debugger session to read runtime memory.");
    }
    populate_watch_view();
    if (debugger_status_label_ != nullptr) {
        debugger_status_label_->setText(tr("Session: idle"));
    }
}

void MainWindow::poll_analysis_job() {
    if (analysis_future_ == nullptr) {
        analysis_poll_timer_->stop();
        return;
    }

    if (analysis_future_->wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        return;
    }

    app::AnalysisJobResult result = analysis_future_->get();
    analysis_future_.reset();
    analysis_poll_timer_->stop();
    set_analysis_busy(false);

    if (!result.success) {
        live_program_.reset();
        statusBar()->showMessage("Analysis failed", 5000);
        show_error("Analysis Failed", tr("Native analysis failed.\n\n%1").arg(to_qstring(result.error)));
        return;
    }

    live_program_ = std::move(result.program);
    if (live_program_->project_cache_hit) {
        append_log(
            output_view_,
            tr("Reused persisted analysis cache.\nProject database: %1").arg(
                QString::fromStdString(current_project_path_.string())
            )
        );
    } else {
        append_log(
            output_view_,
            tr("Analysis completed.\nProject database: %1").arg(QString::fromStdString(current_project_path_.string()))
        );
        app::record_ai_request_usage(settings_, current_ai_settings());
    }
    if (load_project(current_project_path_, true)) {
        statusBar()->showMessage(live_program_->project_cache_hit ? "Reused cached analysis" : "Analysis completed", 5000);
    }
}

std::optional<std::uint64_t> MainWindow::parse_runtime_address(const QString& text) const {
    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty()) {
        return std::nullopt;
    }

    bool ok = false;
    auto value = trimmed.toULongLong(&ok, 0);
    if (!ok && !trimmed.startsWith("0x")) {
        value = trimmed.toULongLong(&ok, 16);
    }
    if (ok) {
        return static_cast<std::uint64_t>(value);
    }

    if (live_program_.has_value()) {
        if (const auto symbol = live_program_->address_space.resolve_symbol(trimmed.toStdString()); symbol.has_value()) {
            return symbol->address;
        }
    }

    return std::nullopt;
}

QString MainWindow::format_symbol_label(const std::uint64_t address) const {
    if (!live_program_.has_value()) {
        return {};
    }

    if (const auto exact = live_program_->address_space.symbol_at(address); exact.has_value()) {
        return to_qstring(exact->name);
    }
    if (const auto nearest = live_program_->address_space.nearest_symbol(address); nearest.has_value()) {
        const auto delta = address - nearest->address;
        if (delta <= 0x400) {
            if (delta == 0U) {
                return to_qstring(nearest->name);
            }
            return QString("%1 +0x%2").arg(to_qstring(nearest->name), QString::number(delta, 16).toUpper());
        }
    }
    return {};
}

std::filesystem::path MainWindow::project_database_path_for_binary(const std::filesystem::path& binary_path) const {
    const QString app_data_root =
        QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation).isEmpty()
            ? QDir::home().filePath(".zara")
            : QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    QDir project_dir(app_data_root);
    project_dir.mkpath("projects");
    const QByteArray digest = QCryptographicHash::hash(
        QString::fromStdString(binary_path.string()).toUtf8(),
        QCryptographicHash::Sha1
    ).toHex()
         .left(12);
    return std::filesystem::path(
        project_dir.filePath(
            QString("projects/%1-%2.sqlite")
                .arg(QString::fromStdString(binary_path.filename().string()), QString::fromLatin1(digest))
        )
            .toStdString()
    );
}

app::AiSettings MainWindow::current_ai_settings() const {
    return app::load_ai_settings(const_cast<QSettings&>(settings_));
}

QString MainWindow::load_ai_secret(const app::AiSettings& config, QString* out_error) const {
    QString secret;
    QString error;
    if (!app::SecretStore::read_secret(app::provider_secret_account(config.provider), secret, error) &&
        out_error != nullptr) {
        *out_error = error;
    }
    return secret;
}

ai::AssistantOptions MainWindow::current_ai_options(const app::AiSettings& config, const QString& secret) const {
    return app::build_assistant_options(config, secret);
}

QString MainWindow::ai_runtime_summary(const app::AiSettings& config) const {
    QString summary = tr("AI provider: %1").arg(app::provider_display_name(config.provider));
    if (!config.model.trimmed().isEmpty()) {
        summary += tr("  |  model: %1").arg(config.model.trimmed());
    }
    if (app::provider_uses_remote_billing(config.provider)) {
        summary += tr("  |  daily cap: %1").arg(
            config.max_remote_requests_per_day <= 0 ? tr("unlimited") : QString::number(config.max_remote_requests_per_day)
        );
    }
    return summary;
}

void MainWindow::open_ai_settings_dialog() {
    const app::AiSettings current = current_ai_settings();

    QDialog dialog(this);
    dialog.setWindowTitle(tr("AI Settings"));
    dialog.resize(620, 0);

    auto* layout = new QVBoxLayout(&dialog);
    auto* intro = new QLabel(
        tr("Choose how Zara should perform model-backed analysis. Hosted providers use your own provider account. Local heuristic analysis stays available as a fallback."),
        &dialog
    );
    intro->setWordWrap(true);
    layout->addWidget(intro);

    auto* form = new QFormLayout();
    auto* provider_combo = new QComboBox(&dialog);
    const std::array providers = {
        app::AiProviderProfile::Heuristic,
        app::AiProviderProfile::OpenAI,
        app::AiProviderProfile::Anthropic,
        app::AiProviderProfile::Gemini,
        app::AiProviderProfile::OpenAICompatible,
        app::AiProviderProfile::LocalLLM,
    };
    int current_index = 0;
    for (std::size_t index = 0; index < providers.size(); ++index) {
        provider_combo->addItem(app::provider_display_name(providers[index]), app::provider_key(providers[index]));
        if (providers[index] == current.provider) {
            current_index = static_cast<int>(index);
        }
    }
    provider_combo->setCurrentIndex(current_index);

    auto* model_edit = new QLineEdit(current.model, &dialog);
    auto* endpoint_edit = new QLineEdit(current.endpoint, &dialog);
    auto* organization_edit = new QLineEdit(current.organization, &dialog);
    auto* project_edit = new QLineEdit(current.project, &dialog);
    auto* api_key_edit = new QLineEdit(&dialog);
    api_key_edit->setEchoMode(QLineEdit::Password);
    auto* max_functions_spin = new QSpinBox(&dialog);
    max_functions_spin->setRange(1, 256);
    max_functions_spin->setValue(std::max(1, current.max_functions_per_run));
    auto* timeout_spin = new QSpinBox(&dialog);
    timeout_spin->setRange(1000, 300000);
    timeout_spin->setSingleStep(1000);
    timeout_spin->setValue(std::max(1000, current.timeout_ms));
    auto* daily_cap_spin = new QSpinBox(&dialog);
    daily_cap_spin->setRange(0, 10000);
    daily_cap_spin->setValue(std::max(0, current.max_remote_requests_per_day));
    auto* fallback_box = new QCheckBox(tr("Fall back to heuristic analysis if the provider request fails"), &dialog);
    fallback_box->setChecked(current.fallback_to_heuristics);
    auto* provider_note = new QLabel(&dialog);
    provider_note->setWordWrap(true);
    auto* storage_note = new QLabel(&dialog);
    storage_note->setWordWrap(true);
    auto* usage_note = new QLabel(
        tr("Cost model: Zara never proxies your hosted requests here. Your provider bills your key directly. Zara only limits request scope with per-run function caps, timeouts, and an optional daily request cap."),
        &dialog
    );
    usage_note->setWordWrap(true);

    form->addRow(tr("Provider"), provider_combo);
    form->addRow(tr("Model"), model_edit);
    form->addRow(tr("Endpoint"), endpoint_edit);
    form->addRow(tr("Organization"), organization_edit);
    form->addRow(tr("Project"), project_edit);
    form->addRow(tr("API key"), api_key_edit);
    form->addRow(tr("Max functions per run"), max_functions_spin);
    form->addRow(tr("Request timeout (ms)"), timeout_spin);
    form->addRow(tr("Daily remote request cap"), daily_cap_spin);
    layout->addLayout(form);
    layout->addWidget(fallback_box);
    layout->addWidget(provider_note);
    layout->addWidget(storage_note);
    layout->addWidget(usage_note);

    auto* buttons =
        new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel | QDialogButtonBox::RestoreDefaults, &dialog);
    layout->addWidget(buttons);

    const auto provider_from_combo = [&]() {
        const auto key = provider_combo->currentData().toString();
        if (key == "openai") {
            return app::AiProviderProfile::OpenAI;
        }
        if (key == "anthropic") {
            return app::AiProviderProfile::Anthropic;
        }
        if (key == "gemini") {
            return app::AiProviderProfile::Gemini;
        }
        if (key == "openai_compatible") {
            return app::AiProviderProfile::OpenAICompatible;
        }
        if (key == "local_llm") {
            return app::AiProviderProfile::LocalLLM;
        }
        return app::AiProviderProfile::Heuristic;
    };

    const auto refresh_provider_fields = [&]() {
        const auto provider = provider_from_combo();
        provider_note->setText(app::provider_help_text(provider));
        model_edit->setPlaceholderText(app::provider_default_model(provider));
        endpoint_edit->setPlaceholderText(app::provider_default_endpoint(provider));
        organization_edit->setEnabled(provider == app::AiProviderProfile::OpenAI);
        project_edit->setEnabled(provider == app::AiProviderProfile::OpenAI);
        api_key_edit->setEnabled(app::provider_requires_api_key(provider) || provider == app::AiProviderProfile::LocalLLM);
        daily_cap_spin->setEnabled(app::provider_uses_remote_billing(provider));

        QString secret;
        QString error;
        const bool secret_read_ok = app::SecretStore::read_secret(app::provider_secret_account(provider), secret, error);
        QString text = app::SecretStore::availability_description();
        if (!secret_read_ok && !error.isEmpty()) {
            text += tr("\n%1").arg(error);
        } else if (!secret.isEmpty()) {
            text += tr("\nA saved key already exists for this provider. Leave the field blank to keep it.");
        }
        storage_note->setText(text);
        api_key_edit->clear();
        if (app::provider_requires_api_key(provider)) {
            api_key_edit->setPlaceholderText(
                !secret.isEmpty() ? tr("Saved in system secret storage. Leave blank to keep.")
                                  : tr("Paste provider API key")
            );
        } else {
            api_key_edit->setPlaceholderText(tr("Optional for local or custom gateways"));
        }
    };

    connect(provider_combo, &QComboBox::currentIndexChanged, &dialog, refresh_provider_fields);
    connect(buttons->button(QDialogButtonBox::RestoreDefaults), &QAbstractButton::clicked, &dialog, [&]() {
        const auto provider = provider_from_combo();
        model_edit->setText(app::provider_default_model(provider));
        endpoint_edit->setText(app::provider_default_endpoint(provider));
        organization_edit->clear();
        project_edit->clear();
        max_functions_spin->setValue(12);
        timeout_spin->setValue(30000);
        daily_cap_spin->setValue(25);
        fallback_box->setChecked(true);
        api_key_edit->clear();
        refresh_provider_fields();
    });
    connect(buttons, &QDialogButtonBox::accepted, &dialog, [&]() {
        const auto provider = provider_from_combo();
        const QString entered_secret = api_key_edit->text().trimmed();
        if (!entered_secret.isEmpty()) {
            QString error;
            if (!app::SecretStore::write_secret(app::provider_secret_account(provider), entered_secret, error)) {
                QMessageBox::warning(
                    &dialog,
                    tr("Secret Storage"),
                    tr("Failed to save the provider key in secure storage.\n\n%1").arg(error)
                );
                return;
            }
        }

        app::AiSettings updated;
        updated.provider = provider;
        updated.model = model_edit->text().trimmed();
        updated.endpoint = endpoint_edit->text().trimmed();
        updated.organization = organization_edit->text().trimmed();
        updated.project = project_edit->text().trimmed();
        updated.fallback_to_heuristics = fallback_box->isChecked();
        updated.max_functions_per_run = max_functions_spin->value();
        updated.timeout_ms = timeout_spin->value();
        updated.max_remote_requests_per_day = daily_cap_spin->value();
        app::save_ai_settings(settings_, updated);
        settings_.sync();
        statusBar()->showMessage(tr("Saved AI settings for %1").arg(app::provider_display_name(updated.provider)), 5000);
        dialog.accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    refresh_provider_fields();
    dialog.exec();
}

void MainWindow::show_about_dialog() {
    QMessageBox::about(
        this,
        tr("About ZARA RE FRAMEWORK"),
        tr("ZARA RE FRAMEWORK is a native reverse engineering workstation for binary analysis, graph reconstruction, decompilation, debugging, and automation.\n\nIt is developed by Regaan R, a security researcher and the founder of ROT Independent Security Research Lab.")
    );
}

void MainWindow::open_binary_dialog() {
    const QString path = QFileDialog::getOpenFileName(this, tr("Open Binary"));
    if (path.isEmpty()) {
        return;
    }
    open_binary(std::filesystem::path(path.toStdString()));
}

void MainWindow::open_project_dialog() {
    const QString path =
        QFileDialog::getOpenFileName(this, tr("Open Project Database"), QString(), tr("SQLite Database (*.sqlite *.db)"));
    if (path.isEmpty()) {
        return;
    }
    load_project(std::filesystem::path(path.toStdString()));
}

void MainWindow::refresh_analysis() {
    if (current_binary_path_.empty()) {
        show_error("No Binary", "Open a binary first.");
        return;
    }
    if (current_project_path_.empty()) {
        current_project_path_ = project_database_path_for_binary(current_binary_path_);
    }
    run_analysis_backend();
}

void MainWindow::run_analysis_backend() {
    if (current_binary_path_.empty()) {
        return;
    }

    if (analysis_future_ != nullptr) {
        show_error("Analysis Running", "An analysis job is already running.");
        return;
    }

    const auto ai_settings = current_ai_settings();
    QString ai_rate_limit_message;
    if (!app::ai_request_allowed(settings_, ai_settings, ai_rate_limit_message)) {
        show_error("AI Request Cap Reached", ai_rate_limit_message);
        return;
    }

    QString secret_error;
    const QString ai_secret = load_ai_secret(ai_settings, &secret_error);
    if (!secret_error.isEmpty()) {
        append_log(output_view_, tr("AI settings warning: %1").arg(secret_error));
    }
    const auto assistant_options = current_ai_options(ai_settings, ai_secret);

    output_view_->setPlainText(
        tr("Analysis log\n\nStarting analysis for %1\nProject database: %2\n%3\n")
            .arg(
                QString::fromStdString(current_binary_path_.filename().string()),
                QString::fromStdString(current_project_path_.string()),
                ai_runtime_summary(ai_settings)
            )
    );
    statusBar()->showMessage(tr("Analyzing %1 ...").arg(QString::fromStdString(current_binary_path_.filename().string())));
    set_analysis_busy(true);
    clear_debugger_views();
    debug_snapshot_.reset();
    breakpoint_addresses_.clear();
    stop_debugger_session();

    const auto binary_path = current_binary_path_;
    const auto project_path = current_project_path_;
    const auto async_assistant_options = assistant_options;
    analysis_future_ = std::make_unique<std::future<app::AnalysisJobResult>>(std::async(
        std::launch::async,
        [binary_path, project_path, async_assistant_options]() {
            app::AnalysisJobResult result;
            result.success = app::AnalysisRunner::analyze_binary_to_project(
                binary_path,
                project_path,
                &async_assistant_options,
                result.program,
                result.error
            );
            return result;
        }
    ));
    analysis_poll_timer_->start();
}

void MainWindow::start_debugger_session() {
    if (debug_session_ && debug_session_->is_active()) {
        workspace_tabs_->setCurrentWidget(debugger_page_);
        return;
    }
    if (current_binary_path_.empty()) {
        show_error("No Binary", "Open a binary or project first.");
        return;
    }
    if (analysis_future_ != nullptr) {
        show_error("Analysis Running", "Wait for the active analysis job to finish before starting the debugger.");
        return;
    }

    std::string error;
    if (!ensure_live_program_loaded(error)) {
        show_error("Program Load Failed", tr("Failed to prepare the loaded program.\n\n%1").arg(to_qstring(error)));
        return;
    }

    debug_session_ = debugger::DebugSession::create_native();
    if (!debug_session_ || !debug_session_->is_supported()) {
        show_error("Debugger Unsupported", "No supported native debugger backend is available on this host.");
        debug_session_.reset();
        return;
    }

    debugger_output_view_->setPlainText(
        tr("Debugger log\n\nLaunching %1 with backend %2\n")
            .arg(
                QString::fromStdString(current_binary_path_.filename().string()),
                to_qstring(std::string(debug_session_->backend_name()))
            )
    );
    clear_debugger_views();
    set_debugger_running(true);
    previous_registers_.reset();

    debugger::StopEvent stop;
    if (!debug_session_->launch(current_binary_path_, {}, stop, error)) {
        set_debugger_running(false);
        debug_session_.reset();
        show_error("Debugger Launch Failed", tr("Failed to launch the debugger session.\n\n%1").arg(to_qstring(error)));
        return;
    }

    workspace_tabs_->setCurrentWidget(debugger_page_);
    append_log(output_view_, tr("[debugger] launched %1").arg(QString::fromStdString(current_binary_path_.string())));
    refresh_debug_snapshot(stop, true);
}

void MainWindow::continue_debugger_session() {
    if (!debug_session_ || !debug_session_->is_active()) {
        return;
    }

    std::string error;
    debugger::StopEvent stop;
    if (!debug_session_->continue_execution(stop, error)) {
        show_error("Debugger Continue Failed", tr("Failed to continue execution.\n\n%1").arg(to_qstring(error)));
        return;
    }
    refresh_debug_snapshot(stop, true);
}

void MainWindow::step_debugger_session() {
    if (!debug_session_ || !debug_session_->is_active()) {
        return;
    }

    std::string error;
    debugger::StopEvent stop;
    if (!debug_session_->single_step(stop, error)) {
        show_error("Debugger Step Failed", tr("Failed to single-step execution.\n\n%1").arg(to_qstring(error)));
        return;
    }
    refresh_debug_snapshot(stop, true);
}

void MainWindow::stop_debugger_session() {
    if (!debug_session_) {
        set_debugger_running(false);
        clear_debugger_views();
        return;
    }

    std::string error;
    if (debug_session_->is_active() && !debug_session_->terminate(error) && !error.empty()) {
        append_log(output_view_, "[debugger] terminate failed: " + to_qstring(error));
    }
    debug_session_.reset();
    debug_snapshot_.reset();
    previous_registers_.reset();
    breakpoint_addresses_.clear();
    clear_debugger_views();
    append_log(debugger_output_view_, "[detached]");
    set_debugger_running(false);
}

void MainWindow::add_breakpoint() {
    if (!debug_session_ || !debug_session_->is_active()) {
        return;
    }

    const auto address = parse_runtime_address(breakpoint_address_edit_->text());
    if (!address.has_value()) {
        show_error("Breakpoint Error", "Enter a valid breakpoint address or resolved symbol name.");
        return;
    }

    std::string error;
    if (!debug_session_->set_breakpoint(*address, error)) {
        show_error("Breakpoint Error", tr("Failed to set breakpoint.\n\n%1").arg(to_qstring(error)));
        return;
    }

    breakpoint_addresses_.insert(*address);
    populate_breakpoints_view();
    breakpoint_address_edit_->clear();
    append_log(debugger_output_view_, tr("[breakpoint] set %1").arg(to_qstring(app::WorkspaceController::format_address(*address))));
}

void MainWindow::remove_selected_breakpoint() {
    if (!debug_session_ || !debug_session_->is_active()) {
        return;
    }

    const auto* item = breakpoints_table_ != nullptr ? breakpoints_table_->currentItem() : nullptr;
    if (item == nullptr) {
        return;
    }

    const auto row = item->row();
    const auto* address_item = breakpoints_table_->item(row, 0);
    if (address_item == nullptr) {
        return;
    }

    const auto address = parse_runtime_address(address_item->text());
    if (!address.has_value()) {
        return;
    }

    std::string error;
    if (!debug_session_->remove_breakpoint(*address, error)) {
        show_error("Breakpoint Error", tr("Failed to remove breakpoint.\n\n%1").arg(to_qstring(error)));
        return;
    }

    breakpoint_addresses_.erase(*address);
    populate_breakpoints_view();
    append_log(debugger_output_view_, tr("[breakpoint] removed %1").arg(to_qstring(app::WorkspaceController::format_address(*address))));
}

void MainWindow::refresh_memory_pane() {
    if (!debug_session_ || !debug_session_->is_active()) {
        return;
    }

    std::optional<std::uint64_t> address = parse_runtime_address(memory_address_edit_->text());
    if (!address.has_value() && debug_snapshot_.has_value()) {
        address = debug_snapshot_->registers.rip;
        memory_address_edit_->setText(to_qstring(app::WorkspaceController::format_address(*address)));
    }
    if (!address.has_value()) {
        show_error("Memory Read Error", "Enter a valid memory address or symbol name.");
        return;
    }
    populate_memory_view(*address);
}

void MainWindow::apply_live_patch() {
    if (!debug_session_ || !debug_session_->is_active()) {
        return;
    }

    std::optional<std::uint64_t> address = parse_runtime_address(memory_address_edit_->text());
    if (!address.has_value() && debug_snapshot_.has_value()) {
        address = debug_snapshot_->registers.rip;
        memory_address_edit_->setText(to_qstring(app::WorkspaceController::format_address(*address)));
    }
    if (!address.has_value()) {
        show_error("Patch Error", "Enter a valid memory address or symbol.");
        return;
    }

    std::vector<std::byte> patch_bytes;
    QString patch_error;
    if (!parse_patch_bytes(patch_bytes_edit_ != nullptr ? patch_bytes_edit_->text() : QString(), patch_bytes, patch_error)) {
        show_error("Patch Error", patch_error);
        return;
    }

    if (patch_overlaps_breakpoints(*address, patch_bytes.size(), breakpoint_addresses_)) {
        show_error("Patch Error", "Remove any breakpoint that overlaps the target patch range before writing bytes.");
        return;
    }

    std::string error;
    if (!debug_session_->write_memory(*address, patch_bytes, error)) {
        show_error("Patch Error", tr("Failed to patch live memory.\n\n%1").arg(to_qstring(error)));
        return;
    }

    if (live_program_.has_value()) {
        (void)live_program_->address_space.patch_bytes(*address, patch_bytes);
    }

    append_log(
        debugger_output_view_,
        tr("[patch] %1 byte(s) at %2")
            .arg(static_cast<qulonglong>(patch_bytes.size()))
            .arg(to_qstring(app::WorkspaceController::format_address(*address)))
    );
    append_log(
        output_view_,
        tr("[debugger] patched %1 byte(s) at %2")
            .arg(static_cast<qulonglong>(patch_bytes.size()))
            .arg(to_qstring(app::WorkspaceController::format_address(*address)))
    );

    populate_memory_view(*address);
    if (debug_snapshot_.has_value()) {
        populate_stack_view(debug_snapshot_->registers);
    }
    workspace_tabs_->setCurrentWidget(debugger_page_);
}

void MainWindow::rename_selected_symbol() {
    if (controller_ == nullptr || controller_->workspace() == nullptr) {
        show_error("No Project", "Open a project before renaming symbols.");
        return;
    }

    std::optional<std::uint64_t> function_entry = active_function_entry_;
    if (!function_entry.has_value() && functions_list_ != nullptr && functions_list_->currentItem() != nullptr) {
        function_entry = functions_list_->currentItem()->data(Qt::UserRole).toULongLong();
    }
    if (!function_entry.has_value()) {
        show_error("Rename Symbol", "Select a function before renaming its symbol.");
        return;
    }

    const auto& functions = controller_->workspace()->functions;
    const auto function_it = std::find_if(
        functions.begin(),
        functions.end(),
        [&](const persistence::FunctionSummary& function) { return function.entry_address == *function_entry; }
    );
    if (function_it == functions.end()) {
        show_error("Rename Symbol", "The selected function is no longer available in the current workspace.");
        return;
    }
    const std::string original_name = function_it->name;

    bool accepted = false;
    QString renamed = QInputDialog::getText(
        this,
        tr("Rename Function Symbol"),
        tr("New function name"),
        QLineEdit::Normal,
        to_qstring(function_it->name),
        &accepted
    ).trimmed();
    if (!accepted) {
        return;
    }
    if (renamed.isEmpty()) {
        show_error("Rename Symbol", "Function names cannot be empty.");
        return;
    }
    for (const auto character : renamed) {
        if (character.isSpace()) {
            show_error("Rename Symbol", "Function names cannot contain whitespace.");
            return;
        }
    }
    if (renamed == to_qstring(function_it->name)) {
        return;
    }

    std::string error;
    int saved_id = 0;
    if (!controller_->save_symbol_rename(
            persistence::SymbolRenameRecord{
                .function_entry = function_it->entry_address,
                .address = function_it->entry_address,
                .target_kind = "function",
                .original_name = original_name,
                .renamed_name = renamed.toStdString(),
                .created_at = {},
                .updated_at = {},
            },
            &saved_id,
            error
        )) {
        show_error("Rename Symbol", tr("Failed to save the renamed symbol.\n\n%1").arg(to_qstring(error)));
        return;
    }

    populate_workspace();
    (void)select_function_entry(*function_entry, false);
    workspace_tabs_->setCurrentWidget(summary_view_);
    if (live_program_.has_value()) {
        (void)live_program_->address_space.add_symbol(
            zara::memory::Symbol{
                .name = renamed.toStdString(),
                .address = *function_entry,
                .size = 0,
                .kind = zara::memory::SymbolKind::User,
            }
        );
    }
    append_log(
        output_view_,
        tr("[symbols] renamed %1 -> %2")
            .arg(to_qstring(original_name), renamed)
    );
    statusBar()->showMessage(tr("Renamed %1 to %2").arg(to_qstring(original_name), renamed), 5000);
}

void MainWindow::add_comment() {
    if (controller_ == nullptr || controller_->workspace() == nullptr) {
        show_error("No Project", "Open a project before adding comments.");
        return;
    }

    const std::uint64_t default_address =
        debug_snapshot_.has_value() ? debug_snapshot_->registers.rip : active_function_entry_.value_or(0U);
    bool ok = false;
    const QString address_text = QInputDialog::getText(
        this,
        tr("Add Comment"),
        tr("Address or symbol"),
        QLineEdit::Normal,
        default_address == 0U ? QString() : to_qstring(app::WorkspaceController::format_address(default_address)),
        &ok
    );
    if (!ok) {
        return;
    }
    const auto address = parse_runtime_address(address_text);
    if (!address.has_value()) {
        show_error("Comment Error", "Enter a valid address or symbol.");
        return;
    }

    const QStringList scopes = {"instruction", "function", "data", "global"};
    const QString scope = QInputDialog::getItem(this, tr("Add Comment"), tr("Scope"), scopes, 0, false, &ok);
    if (!ok || scope.isEmpty()) {
        return;
    }

    const QString body = QInputDialog::getMultiLineText(this, tr("Add Comment"), tr("Comment text"), QString(), &ok);
    if (!ok || body.trimmed().isEmpty()) {
        return;
    }

    persistence::CommentRecord record;
    record.address = *address;
    record.scope = scope.toStdString();
    record.body = body.toStdString();
    record.function_entry = find_function_containing_address(*address);

    std::string error;
    int saved_id = 0;
    if (!controller_->save_comment(record, &saved_id, error)) {
        show_error("Comment Error", tr("Failed to save comment.\n\n%1").arg(to_qstring(error)));
        return;
    }

    populate_workspace();
    workspace_tabs_->setCurrentWidget(annotations_page_);
    statusBar()->showMessage(tr("Saved comment at %1").arg(to_qstring(app::WorkspaceController::format_address(*address))), 4000);
}

void MainWindow::edit_selected_comment() {
    if (controller_ == nullptr || controller_->workspace() == nullptr || comments_table_ == nullptr) {
        return;
    }

    const auto* item = comments_table_->currentItem();
    if (item == nullptr) {
        return;
    }
    const int row = item->row();
    const auto* address_item = comments_table_->item(row, 0);
    if (address_item == nullptr) {
        return;
    }
    const int comment_id = address_item->data(Qt::UserRole).toInt();
    const auto it = std::find_if(
        controller_->workspace()->comments.begin(),
        controller_->workspace()->comments.end(),
        [comment_id](const auto& record) { return record.id == comment_id; }
    );
    if (it == controller_->workspace()->comments.end()) {
        return;
    }

    bool ok = false;
    const QString address_text = QInputDialog::getText(
        this,
        tr("Edit Comment"),
        tr("Address or symbol"),
        QLineEdit::Normal,
        to_qstring(app::WorkspaceController::format_address(it->address)),
        &ok
    );
    if (!ok) {
        return;
    }
    const auto address = parse_runtime_address(address_text);
    if (!address.has_value()) {
        show_error("Comment Error", "Enter a valid address or symbol.");
        return;
    }

    const QStringList scopes = {"instruction", "function", "data", "global"};
    const int current_scope = std::max(0, static_cast<int>(scopes.indexOf(to_qstring(it->scope))));
    const QString scope = QInputDialog::getItem(this, tr("Edit Comment"), tr("Scope"), scopes, current_scope, false, &ok);
    if (!ok || scope.isEmpty()) {
        return;
    }
    const QString body = QInputDialog::getMultiLineText(
        this,
        tr("Edit Comment"),
        tr("Comment text"),
        to_qstring(it->body),
        &ok
    );
    if (!ok || body.trimmed().isEmpty()) {
        return;
    }

    persistence::CommentRecord record = *it;
    record.address = *address;
    record.scope = scope.toStdString();
    record.body = body.toStdString();
    record.function_entry = find_function_containing_address(*address);

    std::string error;
    int saved_id = 0;
    if (!controller_->save_comment(record, &saved_id, error)) {
        show_error("Comment Error", tr("Failed to update comment.\n\n%1").arg(to_qstring(error)));
        return;
    }

    populate_workspace();
    workspace_tabs_->setCurrentWidget(annotations_page_);
}

void MainWindow::delete_selected_comment() {
    if (controller_ == nullptr || controller_->workspace() == nullptr || comments_table_ == nullptr) {
        return;
    }

    const auto* item = comments_table_->currentItem();
    if (item == nullptr) {
        return;
    }
    const int row = item->row();
    const auto* address_item = comments_table_->item(row, 0);
    if (address_item == nullptr) {
        return;
    }
    const int comment_id = address_item->data(Qt::UserRole).toInt();
    if (QMessageBox::question(this, tr("Delete Comment"), tr("Delete the selected comment?")) != QMessageBox::Yes) {
        return;
    }

    std::string error;
    if (!controller_->delete_comment(comment_id, error)) {
        show_error("Comment Error", tr("Failed to delete comment.\n\n%1").arg(to_qstring(error)));
        return;
    }

    populate_workspace();
    workspace_tabs_->setCurrentWidget(annotations_page_);
}

void MainWindow::add_type_annotation() {
    if (controller_ == nullptr || controller_->workspace() == nullptr) {
        show_error("No Project", "Open a project before adding type annotations.");
        return;
    }

    bool ok = false;
    const QStringList targets = {"argument", "local", "return", "register", "memory", "function", "global"};
    const QString target = QInputDialog::getItem(this, tr("Add Type Annotation"), tr("Target kind"), targets, 0, false, &ok);
    if (!ok || target.isEmpty()) {
        return;
    }
    const QString symbol_name = QInputDialog::getText(this, tr("Add Type Annotation"), tr("Symbol / variable name"), QLineEdit::Normal, QString(), &ok);
    if (!ok || symbol_name.trimmed().isEmpty()) {
        return;
    }
    const QString type_name = QInputDialog::getText(this, tr("Add Type Annotation"), tr("Type"), QLineEdit::Normal, QString(), &ok);
    if (!ok || type_name.trimmed().isEmpty()) {
        return;
    }
    const QString note = QInputDialog::getMultiLineText(this, tr("Add Type Annotation"), tr("Notes"), QString(), &ok);
    if (!ok) {
        return;
    }

    persistence::TypeAnnotationRecord record;
    record.target_kind = target.toStdString();
    record.symbol_name = symbol_name.toStdString();
    record.type_name = type_name.toStdString();
    record.note = note.toStdString();
    record.function_entry = active_function_entry_;

    std::string error;
    int saved_id = 0;
    if (!controller_->save_type_annotation(record, &saved_id, error)) {
        show_error("Type Annotation Error", tr("Failed to save type annotation.\n\n%1").arg(to_qstring(error)));
        return;
    }

    populate_workspace();
    workspace_tabs_->setCurrentWidget(annotations_page_);
}

void MainWindow::edit_selected_type_annotation() {
    if (controller_ == nullptr || controller_->workspace() == nullptr || types_table_ == nullptr) {
        return;
    }

    const auto* item = types_table_->currentItem();
    if (item == nullptr) {
        return;
    }
    const int row = item->row();
    const auto* symbol_item = types_table_->item(row, 0);
    if (symbol_item == nullptr) {
        return;
    }
    const int annotation_id = symbol_item->data(Qt::UserRole).toInt();
    const auto it = std::find_if(
        controller_->workspace()->type_annotations.begin(),
        controller_->workspace()->type_annotations.end(),
        [annotation_id](const auto& record) { return record.id == annotation_id; }
    );
    if (it == controller_->workspace()->type_annotations.end()) {
        return;
    }

    bool ok = false;
    const QStringList targets = {"argument", "local", "return", "register", "memory", "function", "global"};
    const int current_target = std::max(0, static_cast<int>(targets.indexOf(to_qstring(it->target_kind))));
    const QString target =
        QInputDialog::getItem(this, tr("Edit Type Annotation"), tr("Target kind"), targets, current_target, false, &ok);
    if (!ok || target.isEmpty()) {
        return;
    }
    const QString symbol_name = QInputDialog::getText(
        this,
        tr("Edit Type Annotation"),
        tr("Symbol / variable name"),
        QLineEdit::Normal,
        to_qstring(it->symbol_name),
        &ok
    );
    if (!ok || symbol_name.trimmed().isEmpty()) {
        return;
    }
    const QString type_name = QInputDialog::getText(
        this,
        tr("Edit Type Annotation"),
        tr("Type"),
        QLineEdit::Normal,
        to_qstring(it->type_name),
        &ok
    );
    if (!ok || type_name.trimmed().isEmpty()) {
        return;
    }
    const QString note = QInputDialog::getMultiLineText(
        this,
        tr("Edit Type Annotation"),
        tr("Notes"),
        to_qstring(it->note),
        &ok
    );
    if (!ok) {
        return;
    }

    persistence::TypeAnnotationRecord record = *it;
    record.target_kind = target.toStdString();
    record.symbol_name = symbol_name.toStdString();
    record.type_name = type_name.toStdString();
    record.note = note.toStdString();

    std::string error;
    int saved_id = 0;
    if (!controller_->save_type_annotation(record, &saved_id, error)) {
        show_error("Type Annotation Error", tr("Failed to update type annotation.\n\n%1").arg(to_qstring(error)));
        return;
    }

    populate_workspace();
    workspace_tabs_->setCurrentWidget(annotations_page_);
}

void MainWindow::delete_selected_type_annotation() {
    if (controller_ == nullptr || controller_->workspace() == nullptr || types_table_ == nullptr) {
        return;
    }

    const auto* item = types_table_->currentItem();
    if (item == nullptr) {
        return;
    }
    const int row = item->row();
    const auto* symbol_item = types_table_->item(row, 0);
    if (symbol_item == nullptr) {
        return;
    }
    const int annotation_id = symbol_item->data(Qt::UserRole).toInt();
    if (QMessageBox::question(this, tr("Delete Type Annotation"), tr("Delete the selected type annotation?")) != QMessageBox::Yes) {
        return;
    }

    std::string error;
    if (!controller_->delete_type_annotation(annotation_id, error)) {
        show_error("Type Annotation Error", tr("Failed to delete type annotation.\n\n%1").arg(to_qstring(error)));
        return;
    }

    populate_workspace();
    workspace_tabs_->setCurrentWidget(annotations_page_);
}

void MainWindow::import_coverage_trace() {
    if (controller_ == nullptr || controller_->workspace() == nullptr) {
        show_error("No Project", "Open a project before importing coverage.");
        return;
    }

    const QString trace_path = QFileDialog::getOpenFileName(this, tr("Import Coverage Trace"));
    if (trace_path.isEmpty()) {
        return;
    }

    std::string error;
    if (!ensure_live_program_loaded(error)) {
        show_error("Coverage Import Failed", tr("Failed to load the live program.\n\n%1").arg(to_qstring(error)));
        return;
    }

    zara::security::CrashTrace trace;
    if (!zara::security::Workflow::parse_trace_file(std::filesystem::path(trace_path.toStdString()), trace, error)) {
        show_error("Coverage Import Failed", tr("Failed to parse the trace file.\n\n%1").arg(to_qstring(error)));
        return;
    }

    const auto report =
        zara::security::Workflow::analyze_fuzzing_surface(current_binary_path_, live_program_->analysis, trace);
    if (!controller_->save_coverage_report(trace, report, error)) {
        show_error("Coverage Import Failed", tr("Failed to persist coverage.\n\n%1").arg(to_qstring(error)));
        return;
    }

    populate_workspace();
    workspace_tabs_->setCurrentWidget(coverage_page_);
    statusBar()->showMessage(tr("Imported coverage trace %1").arg(trace_path), 5000);
}

void MainWindow::switch_selected_thread() {
    if (!debug_session_ || !debug_session_->is_active() || threads_table_ == nullptr) {
        return;
    }

    const auto* item = threads_table_->currentItem();
    if (item == nullptr) {
        return;
    }
    const int row = item->row();
    const auto* thread_item = threads_table_->item(row, 0);
    if (thread_item == nullptr) {
        return;
    }
    const auto thread_id = thread_item->data(Qt::UserRole).toInt();

    std::string error;
    if (!debug_session_->select_thread(thread_id, error)) {
        show_error("Thread Switch Failed", tr("Failed to switch threads.\n\n%1").arg(to_qstring(error)));
        return;
    }

    debugger::StopEvent stop = debug_snapshot_.has_value() ? debug_snapshot_->stop : debugger::StopEvent{};
    if (stop.reason == debugger::StopReason::None) {
        stop.reason = debugger::StopReason::Signal;
    }
    stop.process_id = debug_session_->process_id();
    stop.thread_id = thread_id;
    stop.message = "Switched selected thread.";
    if (!refresh_debug_snapshot(stop, true)) {
        return;
    }
    populate_threads_view();
}

QString MainWindow::evaluate_watch_expression(const QString& expression) const {
    const QString trimmed = expression.trimmed();
    if (trimmed.isEmpty()) {
        return {};
    }

    if (debug_snapshot_.has_value()) {
        const auto lowered = trimmed.toLower();
        const auto& registers = debug_snapshot_->registers;
        const std::array<std::pair<QString, std::uint64_t>, 18> register_values = {{
            {"rip", registers.rip}, {"rsp", registers.rsp}, {"rbp", registers.rbp}, {"rax", registers.rax},
            {"rbx", registers.rbx}, {"rcx", registers.rcx}, {"rdx", registers.rdx}, {"rsi", registers.rsi},
            {"rdi", registers.rdi}, {"r8", registers.r8},   {"r9", registers.r9},   {"r10", registers.r10},
            {"r11", registers.r11}, {"r12", registers.r12}, {"r13", registers.r13}, {"r14", registers.r14},
            {"r15", registers.r15}, {"eflags", registers.eflags},
        }};
        const auto register_it = std::find_if(
            register_values.begin(),
            register_values.end(),
            [&](const auto& entry) { return entry.first == lowered; }
        );
        if (register_it != register_values.end()) {
            return to_qstring(app::WorkspaceController::format_address(register_it->second));
        }
    }

    const auto address = parse_runtime_address(trimmed);
    if (!address.has_value()) {
        return tr("<unresolved>");
    }
    if (!debug_session_ || !debug_session_->is_active()) {
        return to_qstring(app::WorkspaceController::format_address(*address));
    }

    std::string error;
    std::vector<std::byte> bytes;
    if (!debug_session_->read_memory(*address, sizeof(std::uint64_t), bytes, error) || bytes.empty()) {
        return tr("<read failed>");
    }
    return to_qstring(app::WorkspaceController::format_address(read_qword(bytes, 0)));
}

void MainWindow::add_watch_expression() {
    if (watch_expression_edit_ == nullptr) {
        return;
    }
    const QString expression = watch_expression_edit_->text().trimmed();
    if (expression.isEmpty()) {
        return;
    }
    if (std::find(watch_expressions_.begin(), watch_expressions_.end(), expression) == watch_expressions_.end()) {
        watch_expressions_.push_back(expression);
    }
    watch_expression_edit_->clear();
    populate_watch_view();
    persist_session_state();
}

void MainWindow::remove_selected_watch_expression() {
    if (watch_table_ == nullptr || watch_table_->currentItem() == nullptr) {
        return;
    }
    const int row = watch_table_->currentItem()->row();
    if (row < 0 || row >= static_cast<int>(watch_expressions_.size())) {
        return;
    }
    watch_expressions_.erase(watch_expressions_.begin() + row);
    populate_watch_view();
    persist_session_state();
}

void MainWindow::save_workspace_as() {
    const QString path =
        QFileDialog::getSaveFileName(this, tr("Save Workspace"), QString(), tr("Workspace (*.json)"));
    if (path.isEmpty()) {
        return;
    }
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        show_error("Save Failed", tr("Failed to write workspace file."));
        return;
    }
    file.write(QJsonDocument(workspace_payload()).toJson(QJsonDocument::Indented));
    statusBar()->showMessage(tr("Workspace saved to %1").arg(path), 5000);
}

void MainWindow::load_workspace_from_file() {
    const QString path =
        QFileDialog::getOpenFileName(this, tr("Load Workspace"), QString(), tr("Workspace (*.json)"));
    if (path.isEmpty()) {
        return;
    }
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        show_error("Load Failed", tr("Failed to read workspace file."));
        return;
    }
    const auto document = QJsonDocument::fromJson(file.readAll());
    if (!document.isObject()) {
        show_error("Load Failed", tr("Workspace file is invalid."));
        return;
    }
    apply_workspace_payload(document.object(), true);
    statusBar()->showMessage(tr("Workspace loaded from %1").arg(path), 5000);
}

void MainWindow::navigate_back() {
    if (navigation_index_ <= 0) {
        return;
    }
    --navigation_index_;
    update_navigation_actions();
    select_function_entry(navigation_history_[navigation_index_], false);
}

void MainWindow::navigate_forward() {
    if (navigation_index_ + 1 >= static_cast<int>(navigation_history_.size())) {
        return;
    }
    ++navigation_index_;
    update_navigation_actions();
    select_function_entry(navigation_history_[navigation_index_], false);
}

void MainWindow::on_function_changed(QListWidgetItem* current, QListWidgetItem* previous) {
    Q_UNUSED(previous);
    if (current == nullptr) {
        reset_function_views();
        if (workspace_tabs_->currentWidget() == call_graph_view_) {
            render_call_graph();
        }
        return;
    }
    populate_function_auxiliary_views(current->data(Qt::UserRole).toULongLong());
}

void MainWindow::on_call_activated(QListWidgetItem* item) {
    if (item == nullptr || item->data(RoleKind).toString() != "call") {
        return;
    }
    const QString direction = item->data(RoleDirection).toString();
    if (direction == "in") {
        const auto caller_entry = item->data(RolePrimaryAddress).toULongLong();
        if (active_function_entry_.has_value()) {
            highlighted_call_source_ = caller_entry;
            highlighted_call_target_ = *active_function_entry_;
            highlighted_import_target_.clear();
            render_call_graph();
        }
        select_function_entry(caller_entry);
        workspace_tabs_->setCurrentWidget(summary_view_);
        return;
    }
    if (item->data(RoleFlag).toBool()) {
        if (active_function_entry_.has_value()) {
            highlighted_call_source_ = *active_function_entry_;
            highlighted_call_target_.reset();
            highlighted_import_target_ = item->data(RoleLabel).toString();
            render_call_graph();
        }
        const auto row = import_row_by_label_.find(item->data(RoleLabel).toString().toStdString());
        if (row != import_row_by_label_.end()) {
            select_list_row(imports_list_, row->second);
        }
        return;
    }
    const auto target = item->data(RoleSecondaryAddress).toULongLong();
    if (target != 0U) {
        if (active_function_entry_.has_value()) {
            highlighted_call_source_ = *active_function_entry_;
            highlighted_call_target_ = target;
            highlighted_import_target_.clear();
            render_call_graph();
        }
        select_function_entry(target);
        workspace_tabs_->setCurrentWidget(decompiler_view_);
    }
}

void MainWindow::on_import_activated(QListWidgetItem* item) {
    if (item == nullptr) {
        return;
    }
    const auto row = import_row_by_address_.find(item->data(RolePrimaryAddress).toULongLong());
    if (row != import_row_by_address_.end()) {
        select_list_row(imports_list_, row->second);
    }
}

void MainWindow::on_export_activated(QListWidgetItem* item) {
    if (item == nullptr) {
        return;
    }
    const auto address = item->data(RolePrimaryAddress).toULongLong();
    if (address != 0U) {
        select_function_entry(address);
        workspace_tabs_->setCurrentWidget(decompiler_view_);
    }
}

void MainWindow::on_string_activated(QListWidgetItem* item) {
    if (item == nullptr || controller_ == nullptr || controller_->workspace() == nullptr) {
        return;
    }
    const auto target = item->data(RolePrimaryAddress).toULongLong();
    for (const auto& xref : controller_->workspace()->xrefs) {
        if (xref.kind == "string" && xref.to_address == target) {
            if (const auto entry = find_function_containing_address(xref.from_address); entry.has_value()) {
                select_function_entry(*entry);
                workspace_tabs_->setCurrentWidget(summary_view_);
            }
            break;
        }
    }
}

void MainWindow::on_xref_activated(QListWidgetItem* item) {
    if (item == nullptr) {
        return;
    }
    const auto kind = item->data(RoleDirection).toString();
    const auto from_address = item->data(RolePrimaryAddress).toULongLong();
    const auto to_address = item->data(RoleSecondaryAddress).toULongLong();
    const auto label = item->data(RoleLabel).toString().toStdString();
    highlighted_cfg_source_block_ = block_start_for_address(from_address);
    highlighted_cfg_target_block_ = block_start_for_address(to_address);
    render_cfg_graph();

    if (kind == "string") {
        const auto row = string_row_by_address_.find(to_address);
        if (row != string_row_by_address_.end()) {
            select_list_row(strings_list_, row->second);
        }
    } else if (kind == "import") {
        auto row = import_row_by_label_.find(label);
        if (row == import_row_by_label_.end()) {
            const auto by_address = import_row_by_address_.find(to_address);
            if (by_address != import_row_by_address_.end()) {
                select_list_row(imports_list_, by_address->second);
            }
        } else {
            select_list_row(imports_list_, row->second);
        }
    }

    if (const auto entry = find_function_containing_address(to_address); entry.has_value()) {
        select_function_entry(*entry);
        workspace_tabs_->setCurrentWidget(summary_view_);
        return;
    }
    if (const auto entry = find_function_containing_address(from_address); entry.has_value()) {
        select_function_entry(*entry);
        workspace_tabs_->setCurrentWidget(summary_view_);
    }
}

void MainWindow::on_workspace_tab_changed(int index) {
    Q_UNUSED(index);
    if (workspace_tabs_->currentWidget() == call_graph_view_) {
        render_call_graph();
    } else if (workspace_tabs_->currentWidget() == cfg_graph_view_) {
        render_cfg_graph();
    } else if (workspace_tabs_->currentWidget() == hex_view_) {
        load_hex_view(active_function_entry_);
    } else if (workspace_tabs_->currentWidget() == annotations_page_) {
        populate_annotations_view();
    } else if (workspace_tabs_->currentWidget() == coverage_page_) {
        populate_coverage_view();
    } else if (workspace_tabs_->currentWidget() == versions_page_) {
        populate_versions_view();
    } else if (workspace_tabs_->currentWidget() == debugger_page_) {
        if (debug_session_ && debug_session_->is_active()) {
            continue_button_->setFocus();
        } else {
            breakpoint_address_edit_->setFocus();
        }
    }
    persist_session_state();
}

void MainWindow::show_error(const QString& title, const QString& message) {
    QMessageBox::critical(this, title, message);
}

}  // namespace zara::desktop_qt::ui
