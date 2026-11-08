// Punto de entrada del GateBouncer.exe común (Qt): la ventana del firewall sin driver (FirewallWindow). La ventana
// vieja (MainWindow) sigue en la etapa del lanzador protegido. El motor se instala aparte (GateBouncerEngine.exe).
#include "bootstrap.h"
#include "dev/paletteeditor.h"
#include "palette.h"
#include "firewallwindow.h"
#include "i18n.h"
#include "uiscale.h"
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
// palette:<archivo.json> (cambia la paleta en vivo; vacío = la de fábrica), editorshot:<archivo.png> (el editor),
// combo:<objectName>=<índice> (un desplegable de la ventana o del aviso, elegido como lo haría el usuario: también
// emite activated) y dialogshot:<archivo.png> (el diálogo abierto).
// Al terminar los pasos sale. GATEBOUNCER_QA_LANGUAGE=es|en elige el idioma de la corrida (no se guarda).
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
    } else if (step.startsWith("editorshot:")) {
        // El editor de paletas (GATEBOUNCER_PALETTE_EDITOR=1).
        for (auto *w : QApplication::topLevelWidgets())
            if (w->objectName() == "paletteEditor" && w->isVisible()) w->grab().save(step.mid(11));
    } else if (step.startsWith("sampletoast:")) {
        // El aviso de ejemplo del editor de paletas (GATEBOUNCER_PALETTE_EDITOR=1).
        for (auto *w : QApplication::topLevelWidgets())
            if (auto *editor = dynamic_cast<Gate::PaletteEditor *>(w)) {
                editor->showSampleToast();
                QTimer::singleShot(600, qApp, [editor, file = step.mid(12)] {
                    if (auto *t = editor->sampleToast()) t->grab().save(file);
                });
            }
    } else if (step.startsWith("palette:")) {
        // Cambia la paleta en vivo (lo mismo que hace el editor): «palette:» solo vuelve a la de fábrica.
        Gate::Palette::Data data = Gate::Palette::factory();
        if (step.size() > 8 && !Gate::Palette::load(step.mid(8), &data))
            std::fprintf(stderr, "QA: paleta ilegible: %s\n", qPrintable(step));
        Gate::Palette::apply(data);
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
    // El zoom se fija antes de crear la aplicación: Qt lee el factor una sola vez.
    Gate::UiScale::applyBeforeApp(Gate::UiScale::readSavedLevel());
    QApplication app(argc, argv);
    Gate::UiScale::clearEnvironmentAfterApp();
    // QA: GATEBOUNCER_QA_LANGUAGE=es|en fija el idioma de esta corrida sin guardarlo.
    const QString qaLanguage = qEnvironmentVariable("GATEBOUNCER_QA_LANGUAGE");
    Gate::I18n::setLanguage(qaLanguage.isEmpty() ? Gate::I18n::readSaved() : Gate::I18n::fromCode(qaLanguage));
    // Una sola ventana por usuario: arranca sola al iniciar sesión y abrirla de nuevo trae al frente la que corre.
    // Las corridas de QA van en un escritorio aparte y no se cruzan con la del usuario.
    const bool qa = !qEnvironmentVariableIsEmpty("GATEBOUNCER_QA_SHOT") || !qEnvironmentVariableIsEmpty("LGA_HEADLESS_DESKTOP");
    const QString instanceName = "LGA.GateBouncer.Window." + qEnvironmentVariable("USERNAME");
    const bool minimized = app.arguments().contains("--start-minimized");
    // Desarrollo: GATEBOUNCER_PALETTE_EDITOR=1 abre el editor de paletas junto a la ventana. Corre al lado de la
    // instalada (no toma la instancia única) y no busca actualizaciones.
    const bool paletteEditor = !qEnvironmentVariableIsEmpty("GATEBOUNCER_PALETTE_EDITOR");
    QLocalServer instance;
    // Canal de control aparte del de instancia única (ese, a una versión vieja, la trae al frente): «quit» cierra la app
    // como «Salir» de la bandeja. Lo usa el lanzador del modo desarrollo para no tener dos ventanas abiertas.
    QLocalServer control;
    if (!qa && !paletteEditor) {
        // El mutex decide de forma atómica quién es la primera instancia de esta sesión de Windows. Un relanzamiento
        // (cambio de zoom o idioma) espera hasta 10 s a que la ventana anterior termine de cerrarse.
        const bool relaunch = app.arguments().contains("--relaunch");
        HANDLE mutex = CreateMutexW(nullptr, TRUE, L"Local\\LGA.GateBouncer.Window");
        bool taken = GetLastError() == ERROR_ALREADY_EXISTS;
        for (int i = 0; relaunch && taken && i < 50; ++i) {
            if (mutex) CloseHandle(mutex);
            Sleep(200);
            mutex = CreateMutexW(nullptr, TRUE, L"Local\\LGA.GateBouncer.Window");
            taken = GetLastError() == ERROR_ALREADY_EXISTS;
        }
        if (taken) {
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
        control.setSocketOptions(QLocalServer::UserAccessOption);
        control.listen("LGA.GateBouncer.Control." + qEnvironmentVariable("USERNAME"));
    }
    if (!Gate::initialize(app)) {
        std::fprintf(stderr, "No se pudo cargar la fuente del producto.\n");
        return 2;
    }
    // Desarrollo y QA: GATEBOUNCER_PALETTE=<archivo .json> arranca con esa paleta (el editor la puede cambiar).
    if (const QString file = qEnvironmentVariable("GATEBOUNCER_PALETTE"); !file.isEmpty()) {
        Gate::Palette::Data data;
        if (Gate::Palette::load(file, &data)) Gate::Palette::apply(data);
        Gate::applyPalette(app);
    }
    Gate::FirewallWindow window;
    QObject::connect(&instance, &QLocalServer::newConnection, &window, [&instance, &window] {
        while (auto *client = instance.nextPendingConnection()) {
            QObject::connect(client, &QLocalSocket::disconnected, client, &QObject::deleteLater);
            window.bringToFront();
        }
    });
    QObject::connect(&control, &QLocalServer::newConnection, &window, [&control, &window] {
        while (auto *client = control.nextPendingConnection()) {
            QObject::connect(client, &QLocalSocket::disconnected, client, &QObject::deleteLater);
            QObject::connect(client, &QLocalSocket::readyRead, &window, [client, &window] {
                if (client->readAll().trimmed() == "quit") window.quitFromOutside();
            });
        }
    });
    window.startLifecycle(Gate::Lifecycle::makeNativeTraySurface(), minimized);
    std::unique_ptr<Gate::PaletteEditor> editor;
    if (paletteEditor) {
        editor = std::make_unique<Gate::PaletteEditor>(Gate::PaletteEditor::folderFromEnvironment());
        editor->onClosed = [&window] { window.quitFromOutside(); };
        editor->show();
    }
    return app.exec();
}
