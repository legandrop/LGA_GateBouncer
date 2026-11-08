// Punto de entrada del GateBouncer.exe común (Qt): la ventana del firewall sin driver (FirewallWindow). La ventana
// vieja (MainWindow) sigue en la etapa del lanzador protegido. El motor se instala aparte (GateBouncerEngine.exe).
#include "bootstrap.h"
#include "firewallwindow.h"
#include <QAbstractButton>
#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QLineEdit>
#include <QLocalServer>
#include <QLocalSocket>
#include <QTableWidget>
#include <QTimer>
#include <cstdio>
#include <windows.h>

namespace {
// Recorrido de QA sin abrir nada en el escritorio del usuario (se corre en un escritorio aparte):
// GATEBOUNCER_QA_SHOT="<vista>;<pasos separados por coma>"; pasos: wait:<ms>, view:<vista>, size:<ancho>x<alto>,
// row:<fila> (clic en una fila de la tabla),
// click:<objectName> (botón), shot:<archivo.png>, toastshot:<archivo.png> (el aviso fijo),
// toastclick:<objectName> (botón del aviso fijo), type:<objectName>=<texto> (un campo; «%2C» es una coma),
// combo:<objectName>=<índice> (un desplegable de la ventana o del aviso, elegido como lo haría el usuario: también
// emite activated) y dialogshot:<archivo.png> (el diálogo abierto).
// Al terminar los pasos sale.
QWidget *qaFind(Gate::FirewallWindow *window, const QString &name) {
    // Primero lo visible de la ventana (incluye sus diálogos); después el aviso fijo.
    for (auto *w : window->findChildren<QWidget *>(name))
        if (w->isVisible()) return w;
    if (auto *toast = window->accessToast())
        if (auto *w = toast->findChild<QWidget *>(name)) return w;
    return nullptr;
}

void runSteps(Gate::FirewallWindow *window, QStringList steps) {
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
    } else if (step.startsWith("view:")) {
        window->selectView(step.mid(5));
    } else if (step.startsWith("size:")) {
        const auto f = step.mid(5).split('x');
        if (f.size() == 2) window->resize(f[0].toInt(), f[1].toInt());
    } else if (step.startsWith("row:")) {
        // Clic en una fila de la tabla de la vista (Apps, Activity).
        auto *table = window->findChild<QTableWidget *>("fwTable");
        const int row = step.mid(4).toInt();
        if (table && row < table->rowCount()) emit table->cellClicked(row, 0);
        else std::fprintf(stderr, "QA: tabla o fila no encontrada: %s\n", qPrintable(step));
    } else if (step.startsWith("click:")) {
        QAbstractButton *target = nullptr;
        for (auto *b : window->findChildren<QAbstractButton *>(step.mid(6)))
            if (b->isVisible()) target = b;
        if (target && target->isEnabled()) target->click();
        else std::fprintf(stderr, "QA: botón ausente o deshabilitado: %s\n", qPrintable(step));
    } else if (step.startsWith("type:") || step.startsWith("combo:")) {
        const QString spec = step.mid(step.indexOf(':') + 1);
        const QString name = spec.section('=', 0, 0), value = spec.section('=', 1, -1).replace("%2C", ",");
        QWidget *target = qaFind(window, name);
        if (auto *edit = qobject_cast<QLineEdit *>(target)) {
            edit->setText(value);
        } else if (auto *combo = qobject_cast<QComboBox *>(target)) {
            combo->setCurrentIndex(value.toInt());
            emit combo->activated(value.toInt());
        } else {
            std::fprintf(stderr, "QA: campo o desplegable ausente: %s\n", qPrintable(step));
        }
    } else if (step.startsWith("dialogshot:")) {
        QWidget *dialog = QApplication::activeModalWidget();
        if (!dialog)
            for (auto *d : window->findChildren<QDialog *>())
                if (d->isVisible()) dialog = d;
        if (dialog) dialog->grab().save(step.mid(11));
        else std::fprintf(stderr, "QA: no hay diálogo abierto\n");
    }
    QTimer::singleShot(next, qApp, [window, steps] { runSteps(window, steps); });
}

void qaSteps() {
    const QStringList parts = qEnvironmentVariable("GATEBOUNCER_QA_SHOT").split(';');
    if (parts.size() < 2) return;
    QTimer::singleShot(2500, qApp, [view = parts[0], steps = parts[1].split(',')] {
        for (auto *w : QApplication::topLevelWidgets())
            if (auto *window = qobject_cast<Gate::FirewallWindow *>(w)) {
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
    Gate::FirewallWindow window;
    QObject::connect(&instance, &QLocalServer::newConnection, &window, [&instance, &window] {
        while (auto *client = instance.nextPendingConnection()) {
            QObject::connect(client, &QLocalSocket::disconnected, client, &QObject::deleteLater);
            window.bringToFront();
        }
    });
    window.startLifecycle(Gate::Lifecycle::makeNativeTraySurface(), minimized);
    return app.exec();
}
