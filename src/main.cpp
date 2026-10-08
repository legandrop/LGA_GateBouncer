#include "bootstrap.h"
#include "mainwindow.h"
#include <cstdio>

#ifdef GATEBOUNCER_OBSERVER
int runObserver(QApplication &app, Gate::MainWindow &window);
#endif
int main(int argc, char **argv) {
    QApplication app(argc, argv);
    if (!Gate::initialize(app)) {
        std::fprintf(stderr, "No se pudo cargar la fuente del producto.\n");
        return 2;
    }
    Gate::MainWindow window;
#ifdef GATEBOUNCER_OBSERVER
    const int result = runObserver(app, window);
    if (result >= 0)
        return result;
#endif
    window.show();
    return app.exec();
}
