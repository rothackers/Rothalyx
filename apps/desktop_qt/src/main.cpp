#include "zara/desktop_qt/ui/main_window.hpp"

#include <QApplication>
#include <QIcon>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("ZARA RE FRAMEWORK");
    app.setOrganizationName("Zara");
    app.setStyle("Fusion");
    app.setWindowIcon(QIcon(":/zara-re-platform.png"));

    zara::desktop_qt::ui::MainWindow window;
    window.setWindowIcon(app.windowIcon());
    window.show();

    if (argc > 1) {
        const std::filesystem::path input_path(argv[1]);
        const auto extension = input_path.extension().string();
        if (extension == ".sqlite" || extension == ".db") {
            window.load_project(input_path, true);
        } else {
            window.open_binary(input_path, true);
        }
    }

    return app.exec();
}
