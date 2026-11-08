#include "foldertrust.h"
#include "engine/FirewallClient.h"
#include "folder_rule.h"
#include "i18n.h"
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
    const QPair<QString, QString> named{I18n::tr("This app in %1").arg(label(folder)), NamedPrefix + folder};
    QVector<QPair<QString, QString>> s;
    if (signer.isEmpty()) {
        if (repository) s.push_back(named);
        s.push_back({I18n::tr("This file only"), "path"});
        return s;
    }
    s.push_back({I18n::tr("This app, any version"), "app"});
    s.push_back({I18n::tr("This file only"), "path"});
    if (FirewallClient::publisherRuleAllowed(signer)) s.push_back({I18n::tr("All apps from %1").arg(signer), "publisher"});
    if (repository) s.push_back(named);
    return s;
}

bool isFolderScope(const QString &scope) { return scope.startsWith(FolderPrefix) || scope.startsWith(NamedPrefix); }

QString note(const QString &scope, const QString &exePath) {
    if (scope.startsWith(NamedPrefix))
        return I18n::tr("Covers %1 in %2 and its subfolders, also new builds.")
            .arg(QFileInfo(exePath).fileName(), shown(scope.mid(NamedPrefix.size())));
    if (scope.startsWith(FolderPrefix))
        return I18n::tr("Covers every program in %1 and its subfolders, also ones built there later.")
            .arg(shown(scope.mid(FolderPrefix.size())));
    return {};
}

QString problemText(const QString &problem) {
    // Los textos de engine/folder_rule.cpp (Win32, compartido con el motor, sin Qt), como se muestran. Uno que no esté
    // acá queda como lo escribió el motor.
    if (I18n::language() == I18n::Language::English) return problem;
    if (problem == QLatin1String("Choose a folder.")) return I18n::tr("Choose a folder.");
    if (problem == QLatin1String("This is not a valid folder path.")) return I18n::tr("This is not a valid folder path.");
    if (problem == QLatin1String("Choose a folder on a local drive, such as C:\\Projects\\MyApp."))
        return I18n::tr("Choose a folder on a local drive, such as C:\\Projects\\MyApp.");
    if (problem == QLatin1String("A whole drive cannot be trusted. Choose a folder inside it."))
        return I18n::tr("A whole drive cannot be trusted. Choose a folder inside it.");
    if (problem == QLatin1String("Choose a folder on a local drive: not a network, removable or optical drive."))
        return I18n::tr("Choose a folder on a local drive: not a network, removable or optical drive.");
    if (problem == QLatin1String("This folder does not exist.")) return I18n::tr("This folder does not exist.");
    if (problem == QLatin1String("This is a file, not a folder.")) return I18n::tr("This is a file, not a folder.");
    if (problem == QLatin1String("This folder is on a drive mounted inside another folder. Use a drive letter for that "
                                 "drive instead."))
        return I18n::tr("This folder is on a drive mounted inside another folder. Use a drive letter for that drive "
                        "instead.");
    // Los que nombran una carpeta: se separa el dato del texto fijo.
    const auto between = [&problem](const QString &head, const QString &tail, QString &middle) {
        if (!problem.startsWith(head) || !problem.endsWith(tail) || problem.size() <= head.size() + tail.size())
            return false;
        middle = problem.mid(head.size(), problem.size() - head.size() - tail.size());
        return true;
    };
    QString middle;
    // Los rótulos que no son el nombre de una carpeta (o que Windows muestra traducido): el motor los da en inglés.
    const auto place = [](const QString &label) {
        if (label == QLatin1String("A user profile")) return I18n::trc("folder", "A user profile");
        if (label == QLatin1String("The Recycle Bin")) return I18n::trc("folder", "The Recycle Bin");
        if (label == QLatin1String("Desktop")) return I18n::trc("folder", "Desktop");
        if (label == QLatin1String("Documents")) return I18n::trc("folder", "Documents");
        if (label == QLatin1String("Downloads")) return I18n::trc("folder", "Downloads");
        return label;
    };
    const auto found = [&](const QString &head, const QString &tail) {
        const bool ok = between(head, tail, middle);
        if (ok) middle = place(middle);
        return ok;
    };
    if (found({}, " cannot be trusted, nor anything inside it."))
        return I18n::tr("%1 cannot be trusted, nor anything inside it.").arg(middle);
    if (found({}, " cannot be trusted as a whole. Choose a folder inside it."))
        return I18n::tr("%1 cannot be trusted as a whole. Choose a folder inside it.").arg(middle);
    if (found("Folders inside ", " cannot be trusted."))
        return I18n::tr("Folders inside %1 cannot be trusted.").arg(middle);
    if (between("This folder is a link to ", ". Trust the real folder instead.", middle))
        return I18n::tr("This folder is a link to %1. Trust the real folder instead.").arg(middle);
    if (found("This folder holds ", ", which cannot be trusted."))
        return I18n::tr("This folder holds %1, which cannot be trusted.").arg(middle);
    return problem;
}

} // namespace Gate::FolderTrust
