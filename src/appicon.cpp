#include "appicon.h"
#include <QColor>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QHash>
#include <QIcon>
#include <QImage>
#include <QLabel>
#include <QPainter>
#include <QPen>
#include <QPointer>
#include <QSet>
#include <QTimer>
#include <QVector>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <windows.h>
#include <objbase.h>
#include <shellapi.h>

namespace Gate {

QPainterPath genericAppGlyph() {
    QPainterPath path;
    path.addRoundedRect(QRectF(3, 4, 14, 12), 2, 2);
    path.moveTo(3, 7.5);
    path.lineTo(17, 7.5);
    return path;
}

namespace {

QString cacheKey(const QString &path, int glyph, qreal dpr) {
    return path.toLower() + "|" + QString::number(glyph) + "|" + QString::number(dpr);
}

// El glifo genérico en gris, del tamaño de la caja de un ícono (`glyph` - 2).
QPixmap glyphPixmap(int glyph, qreal dpr) {
    static auto *cache = new QHash<QString, QPixmap>;
    const QString key = QString::number(glyph) + "|" + QString::number(dpr);
    const auto found = cache->constFind(key);
    if (found != cache->constEnd()) return *found;
    const int size = glyph - 2;
    QPixmap pm(QSize(size, size) * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    p.scale(size / 20.0, size / 20.0);
    p.setPen(QPen(QColor("#a8a8a8"), 1.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    p.drawPath(genericAppGlyph());
    p.end();
    cache->insert(key, pm);
    return pm;
}

// ---- Carga en segundo plano

struct Job {
    QString key, path;
    int glyph;
    qreal dpr;
};

struct Loader {
    // Lo comparte el hilo de los íconos: la fila y la orden de parar.
    std::mutex mutex;
    std::condition_variable wake;
    std::deque<Job> queue;
    std::atomic<bool> stopping{false};
    bool started = false;
    // Sólo del hilo de la interfaz.
    QObject *gui = nullptr; // vive hasta el fin del proceso: el hilo le manda los resultados
    QHash<QString, QPixmap> done;
    QHash<QString, qint64> failed; // clave -> cuándo falló
    QSet<QString> queued;
    QMultiHash<QString, QPointer<QLabel>> waiting;
    QVector<QPair<QPointer<QObject>, std::function<void()>>> listeners;
    bool notifyPending = false;
};

Loader &loader() {
    // Viven hasta el final del proceso a propósito: destruir pixmaps después de cerrar la aplicación de Qt no es seguro.
    static auto *l = new Loader;
    return *l;
}

// En el hilo de los íconos (con COM): el ícono grande de Windows, achicado al tamaño pedido. Nulo si no hay archivo.
QImage loadIcon(const QString &path, int px) {
    const std::wstring native = QDir::toNativeSeparators(path).toStdWString();
    // Sin el archivo, Windows devolvería el ícono genérico de su extensión: se prefiere el glifo propio.
    if (native.empty() || GetFileAttributesW(native.c_str()) == INVALID_FILE_ATTRIBUTES) return {};
    SHFILEINFOW info{};
    const UINT size = px > GetSystemMetrics(SM_CXSMICON) ? SHGFI_LARGEICON : SHGFI_SMALLICON;
    if (!SHGetFileInfoW(native.c_str(), 0, &info, sizeof(info), SHGFI_ICON | size) || !info.hIcon) return {};
    QImage image = QImage::fromHICON(info.hIcon);
    DestroyIcon(info.hIcon);
    if (image.isNull()) return {};
    if (image.width() != px || image.height() != px)
        image = image.scaled(px, px, Qt::KeepAspectRatio, Qt::SmoothTransformation);
    return image;
}

void finished(const QString &key, qreal dpr, const QImage &image) {
    auto &l = loader();
    l.queued.remove(key);
    QPixmap pm;
    if (image.isNull()) {
        l.failed.insert(key, QDateTime::currentMSecsSinceEpoch());
    } else {
        pm = QPixmap::fromImage(image);
        pm.setDevicePixelRatio(dpr);
        l.done.insert(key, pm);
    }
    for (const auto &label : l.waiting.values(key))
        if (label && !pm.isNull()) label->setPixmap(pm);
    l.waiting.remove(key);
    // Un aviso por tanda, no por ícono: la tabla se repinta una vez.
    if (l.notifyPending) return;
    l.notifyPending = true;
    QTimer::singleShot(40, l.gui, [] {
        auto &l = loader();
        l.notifyPending = false;
        for (int i = int(l.listeners.size()) - 1; i >= 0; --i) {
            if (!l.listeners[i].first) {
                l.listeners.removeAt(i);
                continue;
            }
            l.listeners[i].second();
        }
    });
}

void worker() {
    auto &l = loader();
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    // Es trabajo de fondo: nunca le quita tiempo a la interfaz ni a otra app.
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    for (;;) {
        Job job;
        {
            std::unique_lock<std::mutex> lock(l.mutex);
            l.wake.wait(lock, [&l] { return !l.queue.empty() || l.stopping; });
            if (l.stopping) break;
            job = l.queue.front();
            l.queue.pop_front();
        }
        const QImage image = loadIcon(job.path, qRound(job.glyph * job.dpr));
        if (l.stopping) break;
        QMetaObject::invokeMethod(l.gui, [key = job.key, dpr = job.dpr, image] { finished(key, dpr, image); },
                                  Qt::QueuedConnection);
    }
    CoUninitialize();
}

// Pide un ícono (en el hilo de la interfaz). `urgent`: lo que se ve ahora va antes que lo pedido sin apuro.
void request(const QString &key, const QString &path, int glyph, qreal dpr, bool urgent) {
    auto &l = loader();
    if (!l.gui) {
        l.gui = new QObject;
        if (auto *app = QCoreApplication::instance())
            QObject::connect(app, &QCoreApplication::aboutToQuit, l.gui, [] {
                auto &l = loader();
                l.stopping = true;
                l.wake.notify_all();
            });
    }
    if (l.queued.contains(key)) {
        if (!urgent) return;
        // Ya estaba en la fila sin apuro: pasa adelante.
        std::lock_guard<std::mutex> lock(l.mutex);
        for (auto it = l.queue.begin(); it != l.queue.end(); ++it)
            if (it->key == key) {
                const Job job = *it;
                l.queue.erase(it);
                l.queue.push_front(job);
                break;
            }
        return;
    }
    l.queued.insert(key);
    {
        std::lock_guard<std::mutex> lock(l.mutex);
        if (urgent) l.queue.push_front({key, path, glyph, dpr});
        else l.queue.push_back({key, path, glyph, dpr});
        if (!l.started) {
            l.started = true;
            // Suelto: al salir se le pide que pare (aboutToQuit) y nadie lo espera, por si Windows tarda con un ícono.
            std::thread(worker).detach();
        }
    }
    l.wake.notify_one();
}

// Ya se sabe la respuesta: el ícono, o que no hay (por 5 minutos).
bool known(const QString &key, QPixmap *out) {
    auto &l = loader();
    const auto found = l.done.constFind(key);
    if (found != l.done.constEnd()) {
        *out = *found;
        return true;
    }
    const auto failed = l.failed.constFind(key);
    if (failed != l.failed.constEnd()) {
        if (QDateTime::currentMSecsSinceEpoch() - *failed < 5 * 60 * 1000) return true;
        l.failed.remove(key);
    }
    return false;
}

} // namespace

QPixmap appIconPixmap(const QString &path, int glyph, qreal dpr) {
    static auto *provider = new QFileIconProvider;
    const QString key = cacheKey(path, glyph, dpr);
    // Sólo los íconos ya leídos: un fallo guardado por las listas no vale acá. El aviso le vuelve a preguntar a
    // Windows, por si el programa se acaba de recompilar o reinstalar.
    const auto found = loader().done.constFind(key);
    if (found != loader().done.constEnd()) return *found;
    QPixmap pm;
    if (!path.isEmpty() && QFileInfo::exists(path)) pm = provider->icon(QFileInfo(path)).pixmap(QSize(glyph, glyph), dpr);
    if (!pm.isNull()) {
        loader().done.insert(key, pm);
        loader().failed.remove(key);
        return pm;
    }
    // El glifo no se guarda como respuesta: si el programa aparece después en esa ruta, se ve su ícono real.
    return glyphPixmap(glyph, dpr);
}

namespace AppIcons {

QPixmap get(const QString &path, int glyph, qreal dpr, bool *ready) {
    const QString key = cacheKey(path, glyph, dpr);
    QPixmap pm;
    const bool isKnown = path.isEmpty() || known(key, &pm);
    if (!isKnown) request(key, path, glyph, dpr, true);
    if (ready) *ready = isKnown;
    return pm.isNull() ? glyphPixmap(glyph, dpr) : pm;
}

void apply(QLabel *label, const QString &path, int glyph, qreal dpr) {
    bool ready = false;
    label->setPixmap(get(path, glyph, dpr, &ready));
    if (!ready) loader().waiting.insert(cacheKey(path, glyph, dpr), label);
}

void prefetch(const QStringList &paths, int glyph, qreal dpr) {
    for (const auto &path : paths) {
        if (path.isEmpty()) continue;
        const QString key = cacheKey(path, glyph, dpr);
        QPixmap pm;
        if (!known(key, &pm)) request(key, path, glyph, dpr, false);
    }
}

void onLoaded(QObject *context, std::function<void()> callback) {
    auto &listeners = loader().listeners;
    // Los de tablas que ya no existen se purgan acá también: si no llega ningún ícono, no se juntan sin tope.
    for (int i = int(listeners.size()) - 1; i >= 0; --i)
        if (!listeners[i].first) listeners.removeAt(i);
    listeners.push_back({QPointer<QObject>(context), std::move(callback)});
}

} // namespace AppIcons

} // namespace Gate
