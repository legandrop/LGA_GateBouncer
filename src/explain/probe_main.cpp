// Sonda de comparación de modelos para las explicaciones: con la key guardada por GateBouncer (la de esta cuenta),
// pregunta por una lista de ejecutables a varios modelos y escribe las respuestas y los tiempos en un JSON.
// No decide nada ni toca el firewall. La key nunca se imprime.
//   GateBouncerExplainProbe.exe --list                       (modelos de NVIDIA)
//   GateBouncerExplainProbe.exe --apps <lista.txt> --out <resultado.json> [--models a,b,c] [--language es|en]
//   GateBouncerExplainProbe.exe --store-key-from-env NVIDIA_API_KEY | ANTHROPIC_API_KEY
// lista.txt: una ruta de ejecutable por línea; opcionalmente «ruta|dirección|puerto|firma|servidor».
#include "Explainer.h"
#include "KeyStore.h"
#include "KnownApps.h"
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>
#include <cstdio>

using namespace Gate::Explain;

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    const QStringList args = app.arguments();
    QTextStream out(stdout);
    // Guarda en el vault la key de una variable de entorno (la del archivo .env del usuario), sin pasarla por la
    // línea de comandos ni imprimirla. Es lo mismo que pegarla en Settings.
    // El proveedor sale del nombre de la variable: ANTHROPIC_API_KEY guarda la de Anthropic; el resto, la de NVIDIA.
    if (const auto i = args.indexOf("--store-key-from-env"); i >= 0 && i + 1 < args.size()) {
        const Provider provider = args[i + 1].contains("ANTHROPIC", Qt::CaseInsensitive) ? Provider::Anthropic
                                                                                        : Provider::Nvidia;
        QString key = qEnvironmentVariable(args[i + 1].toLocal8Bit().constData()).trimmed();
        QString error;
        const bool ok = KeyStore::plausible(provider, key) && KeyStore::save(provider, key, error);
        key.fill(QChar(0));
        out << (ok ? providerName(provider) + " key saved for this account.\n"
                   : "Key not saved: " +
                         (error.isEmpty() ? "not an " + providerName(provider) + " API key" : error) + "\n");
        return ok ? 0 : 1;
    }
    if (args.contains("--list")) {
        HttpResult r;
        QString error;
        KeyStore::withKey(
            Provider::Nvidia,
            [&](const std::string &key) { r = providerRequest(Provider::Nvidia, "GET", L"/v1/models", {}, key, 30000); },
            error);
        if (!error.isEmpty() || !r.error.isEmpty() || r.status != 200) {
            out << "Could not list models: " << (error + r.error) << " HTTP " << r.status << "\n";
            return 1;
        }
        for (const auto &m : QJsonDocument::fromJson(r.body).object().value("data").toArray())
            out << m.toObject().value("id").toString() << "\n";
        return 0;
    }
    const auto value = [&](const QString &name) {
        const auto i = args.indexOf(name);
        return i >= 0 && i + 1 < args.size() ? args[i + 1] : QString();
    };
    // Sólo los datos locales que se mandarían, sin pedir nada a ningún proveedor.
    if (!value("--facts").isEmpty()) {
        const auto f = collectFacts(value("--facts"), {}, {}, 0, 0, 0);
        out << "file_name: " << f.fileName << "\nfolder: " << f.folder << "\nlaunched_by: " << f.launchedBy
            << "\nlga_app: " << (Gate::KnownApps::isLgaApp(f.path) ? "yes" : "no") << "\n";
        return 0;
    }
    QStringList models = value("--models").isEmpty() ? Settings::models() : value("--models").split(',');
    const QString language = value("--language").isEmpty() ? QStringLiteral("es") : value("--language");
    QFile list(value("--apps"));
    if (!list.open(QIODevice::ReadOnly | QIODevice::Text) || value("--out").isEmpty()) {
        out << "Usage: --apps <list.txt> --out <result.json> [--models a,b] [--language es|en] | --list\n";
        return 2;
    }
    QJsonArray results;
    for (const QString &line : QString::fromUtf8(list.readAll()).split('\n', Qt::SkipEmptyParts)) {
        const auto parts = line.trimmed().split('|');
        if (parts.isEmpty() || parts[0].isEmpty() || !QFileInfo::exists(parts[0])) continue;
        // Firma: la sonda no tiene el verificador del motor; se pasa la que figure en la lista (cuarto campo).
        const auto facts =
            collectFacts(parts[0], parts.value(3), parts.value(1), parts.value(2).toInt(), 6, 1, parts.value(4));
        for (const auto &model : models) {
            Answer answer;
            QString error;
            qint64 ms = 0;
            const bool ok = explainNow(facts, model.trimmed(), language, answer, error, &ms);
            out << (ok ? "OK   " : "FAIL ") << model << "  " << facts.fileName << "  " << ms << " ms"
                << (ok ? QString() : "  " + error) << "\n";
            out.flush();
            results.append(QJsonObject{{"model", model},
                                       {"app", facts.fileName},
                                       {"folder", facts.folder},
                                       {"ok", ok},
                                       {"ms", double(ms)},
                                       {"error", error},
                                       {"what", answer.what},
                                       {"why", answer.why},
                                       {"risk", answer.risk},
                                       {"suggestion", answer.suggestion},
                                       {"reason", answer.reason}});
        }
    }
    QFile file(value("--out"));
    if (!file.open(QIODevice::WriteOnly)) return 1;
    file.write(QJsonDocument(results).toJson(QJsonDocument::Indented));
    return 0;
}
