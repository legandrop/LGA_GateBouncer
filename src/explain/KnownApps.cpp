#include "KnownApps.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <vector>

namespace Gate::KnownApps {
namespace {

struct Entry {
    QString signer, file, destination, decision, what;
};

// Igual que el motor: «*.dominio» incluye el dominio pelado y sus subdominios.
bool matchesDestination(const QString &pattern, const QString &host) {
    if (!pattern.startsWith("*.")) return host == pattern;
    const QString suffix = pattern.mid(2);
    return host == suffix || host.endsWith("." + suffix);
}

const std::vector<Entry> &entries() {
    static const std::vector<Entry> list = [] {
        std::vector<Entry> out;
        // QA: un catálogo de prueba en lugar del que viaja con la app, sólo en un recorrido de QA (como el resto de
        // los ganchos de QA de app_main.cpp): la ventana instalada no lee un catálogo de otro lado.
        const QString qa = qEnvironmentVariableIsEmpty("GATEBOUNCER_QA_SHOT") ? QString()
                                                                              : qEnvironmentVariable("GATEBOUNCER_QA_CATALOG");
        QFile file(qa.isEmpty() ? QStringLiteral(":/gatebouncer/resources/catalog/known_apps.json") : qa);
        if (!file.open(QIODevice::ReadOnly)) return out;
        for (const auto &v : QJsonDocument::fromJson(file.readAll()).object().value("apps").toArray()) {
            const auto o = v.toObject();
            Entry e{o.value("signer").toString(), o.value("file").toString().toLower(),
                    o.value("destination").toString().toLower(), o.value("decision").toString(),
                    o.value("what").toString().simplified().left(300)};
            if (!e.signer.isEmpty() && !e.file.isEmpty() && (e.decision == "allow" || e.decision == "block"))
                out.push_back(e);
        }
        return out;
    }();
    return list;
}

} // namespace

static QString catalogHint(const QString &signer, const QString &path, const QString &host) {
    if (signer.isEmpty()) return {};
    const QString file = QFileInfo(path).fileName().toLower();
    const QString name = host.toLower();
    const Entry *app = nullptr, *destination = nullptr;
    for (const auto &e : entries()) {
        if (e.file != file || e.signer.compare(signer, Qt::CaseInsensitive) != 0) continue;
        if (e.destination.isEmpty()) app = &e;
        else if (!name.isEmpty() && matchesDestination(e.destination, name)) destination = &e;
    }
    // Lo dicho para ese destino manda sobre lo dicho para la app entera.
    const Entry *e = destination ? destination : app;
    if (!e) return {};
    const QString verdict = e->decision == "allow" ? QStringLiteral("Allow") : QStringLiteral("Block");
    const QString scope = destination ? " for " + e->destination : QString();
    return "Known app · usually " + verdict + scope + (e->what.isEmpty() ? QString() : " · " + e->what);
}

QString hint(const QString &signer, const QString &path, const QString &host) {
    const QString known = catalogHint(signer, path, host);
    if (!known.isEmpty() || !isLgaApp(path)) return known;
    return QStringLiteral("LGA app · usually Allow · From an LGA app folder. LGA apps connect to update themselves or "
                          "for a feature that needs the internet.");
}

QString suggestion(const QString &hint) {
    const QString verdict = hint.section(" · ", 1, 1);
    return verdict.startsWith("usually Allow") ? QStringLiteral("allow")
           : verdict.startsWith("usually Block") ? QStringLiteral("block")
                                                 : QString();
}

// shortcut: sólo la carpeta, y C:\Portable lo puede escribir el usuario: cualquier exe que caiga ahí recibe la
// recomendación. Alcanza porque es sólo una recomendación (el clic sigue siendo del usuario y, sin firma, la regla
// cubre ese archivo exacto); pasar a la firma cuando las apps LGA se firmen.
bool isLgaApp(const QString &path) {
    static const QRegularExpression folder(
        QStringLiteral("^c:/(portable/lga/[^/]+/|program files/lga [^/]+/|portable/lga_[^/]+/build[^/]*/)"));
    return folder.match(QDir::fromNativeSeparators(path).toLower()).hasMatch();
}

} // namespace Gate::KnownApps
