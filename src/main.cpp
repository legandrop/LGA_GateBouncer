#include "bootstrap.h"
#include "mainwindow.h"
#include <cstdio>
#include <QDir>

#ifdef GATEBOUNCER_OBSERVER
int runObserver(QApplication &app, Gate::MainWindow &window);
#endif
int main(int argc, char **argv) {
    QApplication app(argc, argv);
    if (!Gate::initialize(app)) {
        std::fprintf(stderr, "No se pudo cargar la fuente del producto.\n");
        return 2;
    }
#ifdef GATEBOUNCER_OBSERVER
    const int rootIndex = app.arguments().indexOf("--qa-root");
    const QString qaRoot = rootIndex < 0 ? QString{} : app.arguments().value(rootIndex + 1);
    if (qaRoot.isEmpty() || !QDir::isAbsolutePath(qaRoot)) {
        std::fprintf(stderr, "QA requiere una raiz absoluta exclusiva.\n");
        return 2;
    }
    Gate::MainWindow window(nullptr, true, qaRoot);
    const int result = runObserver(app, window);
    if (result >= 0)
        return result;
#else
    Gate::MainWindow window;
    auto startup = std::make_unique<Gate::Lifecycle::StartupPreference>(
        QCoreApplication::applicationFilePath(), Gate::Lifecycle::makeNativeRunBackend(),
        Gate::Lifecycle::makeOrdinaryGuiDeploymentValidator());
    window.startLifecycle(Gate::Lifecycle::makeNativeTraySurface(),
                          app.arguments().contains("--start-minimized"), std::move(startup));
#endif
#ifdef GATEBOUNCER_OBSERVER
    window.show();
#endif
    return app.exec();
}
