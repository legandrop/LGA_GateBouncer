#include "foldertrust.h"
#include "engine/FirewallClient.h"
#include "folder_rule.h"
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QHash>

namespace Gate::FolderTrust {

namespace {
struct Cached {
    qint64 at = 0;
    QString folder;
    bool repository = false;
};

const QString FolderPrefix = QStringLiteral("folder:");
const QString NamedPrefix = QStringLiteral("foldername:");
} // namespace

QString shown(const QString &folder) {
    // Un word joiner (invisible) después de «C:»: el renglón no se corta ahí.
    QString text = QDir::toNativeSeparators(folder);
    if (text.size() > 2 && text.at(1) == ':') text.insert(2, QChar(0x2060));
    return text;
}

QString problem(const QString &folder) {
    gbe::FinalPath resolved;
    return QString::fromStdWString(gbe::resolveTrustedFolder(QDir::toNativeSeparators(folder).toStdWString(), resolved));
}

QString suggestion(const QString &exePath, bool *inRepository) {
    if (inRepository) *inRepository = false;
    // Sin ruta, QFileInfo daría la carpeta actual de la ventana: no hay nada que proponer.
    if (exePath.trimmed().isEmpty()) return {};
    static QHash<QString, Cached> cache;
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const QString cacheKey = exePath.toLower();
    auto hit = cache.constFind(cacheKey);
    if (hit == cache.constEnd() || now - hit->at > 15000) {
        if (cache.size() > 200) cache.clear();
        Cached c;
        c.at = now;
        const QString own = QDir::toNativeSeparators(QFileInfo(exePath).absolutePath());
        // El repositorio más cercano hacia arriba: la carpeta con «.git» como carpeta. En un worktree «.git» es un archivo
        // que apunta al repositorio principal, así que se sigue subiendo hasta él (C:\Portable\LGA_DayTrace). Si arriba no
        // hay repositorio (un worktree en otra carpeta), queda el worktree.
        QString repository, worktree;
        for (QDir dir(own); !dir.isRoot();) {
            const QFileInfo git(dir.filePath(".git"));
            if (git.isDir()) {
                repository = QDir::toNativeSeparators(dir.absolutePath());
                break;
            }
            if (git.isFile() && worktree.isEmpty()) worktree = QDir::toNativeSeparators(dir.absolutePath());
            if (!dir.cdUp()) break;
        }
        if (!repository.isEmpty() && problem(repository).isEmpty()) {
            c.folder = repository;
            c.repository = true;
        } else if (!worktree.isEmpty() && problem(worktree).isEmpty()) {
            c.folder = worktree;
            c.repository = true;
        } else if (problem(own).isEmpty()) {
            c.folder = own;
        }
        hit = cache.insert(cacheKey, c);
    }
    if (inRepository) *inRepository = hit->repository;
    return hit->folder;
}

QString label(const QString &folder) {
    const QString name = QFileInfo(QDir::fromNativeSeparators(folder)).fileName();
    return name.isEmpty() ? QDir::toNativeSeparators(folder) : name;
}

bool contains(const QString &folder, const QString &path) {
    const QString f = QDir::fromNativeSeparators(folder).toLower();
    const QString p = QDir::fromNativeSeparators(path).toLower();
    return !f.isEmpty() && p.size() > f.size() + 1 && p.startsWith(f) && p.at(f.size()) == '/';
}

QVector<QPair<QString, QString>> scopeChoices(const QString &exePath, const QString &signer, bool perDestination) {
    bool inRepository = false;
    const QString folder = perDestination ? QString() : suggestion(exePath, &inRepository);
    const bool repository = !folder.isEmpty() && inRepository;
    // Corta, como «This app, any version»: lo que cubre exacto (el nombre y la carpeta entera) va en note().
    const QPair<QString, QString> named{"This app in " + label(folder), NamedPrefix + folder};
    QVector<QPair<QString, QString>> s;
    if (signer.isEmpty()) {
        if (repository) s.push_back(named);
        s.push_back({"This file only", "path"});
        return s;
    }
    s.push_back({"This app, any version", "app"});
    s.push_back({"This file only", "path"});
    if (FirewallClient::publisherRuleAllowed(signer)) s.push_back({"All apps from " + signer, "publisher"});
    if (repository) s.push_back(named);
    return s;
}

bool isFolderScope(const QString &scope) { return scope.startsWith(FolderPrefix) || scope.startsWith(NamedPrefix); }

QString note(const QString &scope, const QString &exePath) {
    if (scope.startsWith(NamedPrefix))
        return QString("Covers %1 in %2 and its subfolders, also new builds.")
            .arg(QFileInfo(exePath).fileName(), shown(scope.mid(NamedPrefix.size())));
    if (scope.startsWith(FolderPrefix))
        return QString("Covers every program in %1 and its subfolders, also ones built there later.")
            .arg(shown(scope.mid(FolderPrefix.size())));
    return {};
}

} // namespace Gate::FolderTrust
