#include <QApplication>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>

#include <filesystem>
#include <iostream>

#define private public
#include "zara/desktop_qt/ui/main_window.hpp"
#undef private

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication application(argc, argv);

    zara::desktop_qt::ui::MainWindow window;

    if (window.debugger_page_ == nullptr || window.debugger_status_label_ == nullptr ||
        window.watch_table_ == nullptr || window.breakpoints_table_ == nullptr ||
        window.threads_table_ == nullptr || window.call_stack_table_ == nullptr ||
        window.debugger_memory_view_ == nullptr) {
        std::cerr << "expected debugger panes to be constructed\n";
        return 1;
    }

    window.set_debugger_running(true);
    if (window.debugger_status_label_->text() != "Session: active" ||
        !window.add_breakpoint_button_->isEnabled() ||
        !window.refresh_memory_button_->isEnabled() ||
        !window.add_watch_button_->isEnabled()) {
        std::cerr << "expected active debugger controls and status\n";
        return 2;
    }

    window.watch_expressions_ = {"rip", "rsp+0x10"};
    window.memory_address_edit_->setText("0x401000");
    window.breakpoint_address_edit_->setText("0x401010");
    const QJsonObject payload = window.workspace_payload();

    zara::desktop_qt::ui::MainWindow restored;
    restored.apply_workspace_payload(payload, false);
    if (restored.watch_expressions_.size() != 2 ||
        restored.memory_address_edit_->text() != "0x401000" ||
        restored.breakpoint_address_edit_->text() != "0x401010") {
        std::cerr << "expected debugger workspace payload round-trip\n";
        return 3;
    }

    restored.populate_watch_view();
    if (restored.watch_table_->rowCount() != 2 || restored.watch_table_->item(0, 0)->text() != "rip") {
        std::cerr << "expected watch table population\n";
        return 4;
    }

    restored.set_debugger_running(false);
    if (restored.debugger_status_label_->text() != "Session: idle" ||
        restored.add_breakpoint_button_->isEnabled() ||
        restored.refresh_memory_button_->isEnabled()) {
        std::cerr << "expected idle debugger controls and status\n";
        return 5;
    }

    return 0;
}
