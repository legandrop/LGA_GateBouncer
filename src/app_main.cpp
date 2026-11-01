// Punto de entrada del GateBouncer.exe común (Qt). La misma interfaz que la etapa cargada por el lanzador
// protegido, sin exigir esa instalación: el motor sin driver se instala aparte (GateBouncerEngine.exe).
#include "bootstrap.h"
#include "mainwindow.h"
#include <QAbstractButton>
#include <QApplication>
#include <QLocalServer>
#include <QLocalSocket>
#include <QTableView>
#include <QTimer>
#include <cstdio>
#include <windows.h>

namespace {
// Recorrido de QA sin abrir nada en el escritorio del usuario (se corre en un escritorio aparte):
// GATEBOUNCER_QA_SHOT="<vista>;<pasos separados por coma>"; pasos: wait:<ms>, row:<fila>:<columna> (clic en la
// tabla), click:<objectName> (botón), shot:<archivo.png>, toastshot:<archivo.png> (el aviso fijo) y
// toastclick:<objectName> (botón del aviso fijo). Al terminar los pasos sale.
void runSteps(Gate::MainWindow *window, QStringList steps) {
    if (steps.isEmpty()) {
        QApplication::exit(0);
        return;
    }
    const QString step = steps.takeFirst();
    int next = 400;
    if (step.startsWith("wait:")) {
        next = step.mid(5).toInt();
    } else if (step.startsWith("shot:")) {
        window->grab().save(step.mid(5));
    } else if (step.startsWith("toastshot:")) {
        if (auto *toast = window->accessToast()) toast->grab().save(step.mid(10));
        else std::fprintf(stderr, "QA: no hay aviso fijo visible\n");
    } else if (step.startsWith("toastclick:")) {
        // Botón del aviso fijo por objectName (toastAllow, toastBlock, toastClose).
        auto *toast = window->accessToast();
        auto *target = toast ? toast->findChild<QAbstractButton *>(step.mid(11)) : nullptr;
        if (target && target->isEnabled()) target->click();
        else std::fprintf(stderr, "QA: botón del aviso ausente o deshabilitado: %s\n", qPrintable(step));
    } else if (step.startsWith("row:")) {
        const auto f = step.split(':');
        auto *table = window->findChild<QTableView *>(window->view() + "-table");
        if (table && f.size() == 3) {
            const auto index = table->model()->index(f[1].toInt(), f[2].toInt());
            table->setCurrentIndex(index);
            emit table->clicked(index);
        } else {
            std::fprintf(stderr, "QA: tabla o fila no encontrada: %s\n", qPrintable(step));
        }
    } else if (step.startsWith("click:")) {
        QAbstractButton *target = nullptr;
        for (auto *b : window->findChildren<QAbstractButton *>(step.mid(6)))
            if (b->isVisible()) target = b;
        if (target && target->isEnabled()) target->click();
        else std::fprintf(stderr, "QA: botón ausente o deshabilitado: %s\n", qPrintable(step));
    }
    QTimer::singleShot(next, qApp, [window, steps] { runSteps(window, steps); });
}

void qaSteps() {
    const QStringList parts = qEnvironmentVariable("GATEBOUNCER_QA_SHOT").split(';');
    if (parts.size() < 2) return;
    QTimer::singleShot(2500, qApp, [view = parts[0], steps = parts[1].split(',')] {
        for (auto *w : QApplication::topLevelWidgets())
            if (auto *window = qobject_cast<Gate::MainWindow *>(w)) {
                window->selectView(view);
                QTimer::singleShot(800, qApp, [window, steps] { runSteps(window, steps); });
                return;
            }
        QApplication::exit(3);
    });
}
Q_COREAPP_STARTUP_FUNCTION(qaSteps)
} // namespace

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    // Una sola ventana por usuario: arranca sola al iniciar sesión y abrirla de nuevo trae al frente la que corre.
    // Las corridas de QA van en un escritorio aparte y no se cruzan con la del usuario.
    const bool qa = !qEnvironmentVariableIsEmpty("GATEBOUNCER_QA_SHOT") || !qEnvironmentVariableIsEmpty("LGA_HEADLESS_DESKTOP");
    const QString instanceName = "LGA.GateBouncer.Window." + qEnvironmentVariable("USERNAME");
    const bool minimized = app.arguments().contains("--start-minimized");
    QLocalServer instance;
    if (!qa) {
        // El mutex decide de forma atómica quién es la primera instancia de esta sesión de Windows.
        CreateMutexW(nullptr, TRUE, L"Local\\LGA.GateBouncer.Window");
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            // Un arranque al iniciar sesión (minimizado) no abre la ventana que ya corre; abrirla a mano, sí.
            if (!minimized) {
                QLocalSocket running;
                running.connectToServer(instanceName);
                if (running.waitForConnected(2000)) {
                    running.write("show\n");
                    running.waitForBytesWritten(1000);
                }
            }
            return 0;
        }
        instance.setSocketOptions(QLocalServer::UserAccessOption);
        instance.listen(instanceName);
    }
    if (!Gate::initialize(app)) {
        std::fprintf(stderr, "No se pudo cargar la fuente del producto.\n");
        return 2;
    }
    Gate::MainWindow window;
    QObject::connect(&instance, &QLocalServer::newConnection, &window, [&instance, &window] {
        while (auto *client = instance.nextPendingConnection()) {
            QObject::connect(client, &QLocalSocket::disconnected, client, &QObject::deleteLater);
            window.bringToFront();
        }
    });
    window.enableNativeAssistance();
    auto startup = std::make_unique<Gate::Lifecycle::StartupPreference>(
        QCoreApplication::applicationFilePath(), Gate::Lifecycle::makeNativeRunBackend(),
        Gate::Lifecycle::makeOrdinaryGuiDeploymentValidator());
    window.startLifecycle(Gate::Lifecycle::makeNativeTraySurface(),
                          minimized, std::move(startup));
    return app.exec();
}
