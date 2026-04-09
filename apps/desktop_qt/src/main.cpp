#include "rothalyx/desktop_qt/ui/main_window.hpp"

#include <QApplication>
#include <QIcon>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("ROTHALYX RE FRAMEWORK");
    app.setOrganizationName("Rothalyx");
    app.setStyle("Fusion");
    app.setWindowIcon(QIcon(":/rothalyx-re-framework.png"));

    rothalyx::desktop_qt::ui::MainWindow window;
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
