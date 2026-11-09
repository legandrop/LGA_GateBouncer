#include "rulestransfer.h"
#include "foldertrust.h"
#include "i18n.h"
#include <QCoreApplication>
#include <QDate>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocale>
#include <QRegularExpression>
#include <QSet>

namespace Gate::RulesTransfer {
namespace {

constexpr char Format[] = "LGA GateBouncer rules";
constexpr int Version = 1;

QString lower(const QString &s) { return s.toLower(); }
QString native(const QString &path) { return QDir::toNativeSeparators(path.trimmed()); }

// Lo que se compara para saber si dos reglas son «la misma» (sin la acción ni el destino).
QString identity(const QString &scope, const QString &path, const QString &signer, const QString &name) {
    if (scope == QLatin1String("path")) return "path|" + lower(native(path));
    if (scope == QLatin1String("app")) return "app|" + lower(signer) + "|" + lower(name);
    if (scope == QLatin1String("publisher")) return "publisher|" + lower(signer);
    if (scope == QLatin1String("folder")) return "folder|" + lower(native(path)) + "|" + lower(name);
    return {};
}
QString identity(const Rule &r) { return identity(r.scope, r.path, r.signer, r.name); }
QString identity(const FirewallClient::RuleItem &r) { return identity(r.scope, r.path, r.signer, r.name); }

FirewallClient::RuleItem asItem(const Rule &r) {
    FirewallClient::RuleItem item;
    item.allow = r.allow;
    item.scope = r.scope;
    item.path = r.path;
    item.signer = r.signer;
    item.name = r.name;
    item.destination = r.destination;
    return item;
}

// Un campo del archivo viaja por el canal separado por tabuladores: nada de caracteres de control.
bool clean(const QString &s, int max) {
    if (s.size() > max) return false;
    for (const QChar c : s)
        if (c.unicode() < 0x20 || c.unicode() == 0x7f) return false;
    return true;
}
// Ruta absoluta de Windows: «C:\…» o «\\servidor\…».
bool absolutePath(const QString &p) {
    static const QRegularExpression drive(QStringLiteral("^[A-Za-z]:\\\\"));
    return drive.match(p).hasMatch() || (p.startsWith(QLatin1String("\\\\")) && p.size() > 2);
}
// Destino como lo acepta DECIDE: host, «*.dominio» o IP (también IPv6).
bool destinationOk(const QString &d) {
    static const QRegularExpression allowed(QStringLiteral("^[A-Za-z0-9._:*\\[\\]-]+$"));
    return d.isEmpty() || (d.size() <= 253 && allowed.match(d).hasMatch());
}
// Nombre de un exe, sin carpeta.
bool fileNameOk(const QString &n) {
    return clean(n, 260) && !n.contains('\\') && !n.contains('/') && !n.contains(':') && !n.contains('*');
}

QString shownDate(const QString &iso) {
    const QDateTime t = QDateTime::fromString(iso, Qt::ISODate);
    if (!t.isValid()) return iso;
    return I18n::language() == I18n::Language::Spanish ? QLocale(QLocale::Spanish).toString(t.toLocalTime(), "d MMM yyyy")
                                                        : QLocale(QLocale::English).toString(t.toLocalTime(), "MMM d, yyyy");
}

// Lo que se puede decir de una entrada que no sirve, para mostrarla salteada.
QString whatOf(const QJsonObject &o) {
    for (const char *key : {"name", "path", "signer"}) {
        const QString v = o.value(key).toString().trimmed();
        if (!v.isEmpty()) return v.left(120).simplified();
    }
    return I18n::tr("Unnamed entry");
}

} // namespace

QString defaultFileName() {
    return QStringLiteral("GateBouncer rules %1.gbrules").arg(QDate::currentDate().toString("yyyy-MM-dd"));
}

QString backupFolder() {
    QString base = qEnvironmentVariable("LOCALAPPDATA");
    if (base.isEmpty()) base = QDir::homePath() + "/AppData/Local";
    return QDir::toNativeSeparators(QDir(base).filePath("LGA/GateBouncer/Backups"));
}

QVector<FirewallClient::RuleItem> exportable(const QVector<FirewallClient::RuleItem> &rules, bool full) {
    QVector<FirewallClient::RuleItem> out;
    for (const auto &r : rules) {
        if (r.expires != 0) continue;
        const bool signature = r.scope == QLatin1String("app") || r.scope == QLatin1String("publisher");
        const bool local = r.scope == QLatin1String("path") || r.scope == QLatin1String("folder");
        if (signature || (full && local && !r.path.isEmpty())) out.push_back(r);
    }
    return out;
}

QByteArray build(const QVector<FirewallClient::RuleItem> &rules, const FirewallClient::Status &status, bool full) {
    QJsonObject root;
    root["format"] = Format;
    root["version"] = Version;
    root["kind"] = full ? "full" : "share";
    const QDateTime now = QDateTime::currentDateTime();
    root["exported"] = now.toOffsetFromUtc(now.offsetFromUtc()).toString(Qt::ISODate);
    root["app"] = QCoreApplication::applicationVersion();
    if (full) {
        QJsonObject protection;
        protection["ask"] = status.ask;
        protection["localNetwork"] = status.localNetwork;
        root["protection"] = protection;
    }
    QJsonArray list;
    for (const auto &r : exportable(rules, full)) {
        QJsonObject o;
        o["action"] = r.allow ? "allow" : "block";
        o["scope"] = r.scope;
        if (r.scope == QLatin1String("path")) {
            o["path"] = native(r.path);
            o["destination"] = r.destination;
        } else if (r.scope == QLatin1String("app")) {
            o["signer"] = r.signer;
            o["name"] = r.name;
            o["destination"] = r.destination;
        } else if (r.scope == QLatin1String("publisher")) {
            o["signer"] = r.signer;
            o["destination"] = r.destination;
        } else { // folder: para la app entera, sin destino
            o["path"] = native(r.path);
            o["name"] = r.name;
        }
        list.append(o);
    }
    root["rules"] = list;
    return QJsonDocument(root).toJson(QJsonDocument::Indented);
}

bool read(const QString &fileName, File &out, QString &error) {
    QFile f(fileName);
    if (!f.open(QIODevice::ReadOnly)) {
        error = I18n::tr("The file could not be opened.");
        return false;
    }
    if (f.size() > MaxFileBytes) {
        error = I18n::tr("The file is larger than 8 MB.");
        return false;
    }
    return parse(f.read(MaxFileBytes + 1), out, error);
}

bool parse(const QByteArray &bytes, File &out, QString &error) {
    out = {};
    error.clear();
    if (bytes.size() > MaxFileBytes) {
        error = I18n::tr("The file is larger than 8 MB.");
        return false;
    }
    QJsonParseError jsonError;
    const QJsonDocument doc = QJsonDocument::fromJson(bytes, &jsonError);
    const QJsonObject root = doc.object();
    if (jsonError.error != QJsonParseError::NoError || !doc.isObject() || root.value("format").toString() != Format ||
        !root.value("rules").isArray()) {
        error = I18n::tr("This is not a GateBouncer rules file.");
        return false;
    }
    const int version = root.value("version").toInt(0);
    if (version > Version) {
        error = I18n::tr("This file was made by a newer GateBouncer. Update GateBouncer to import it.");
        return false;
    }
    if (version < 1) {
        error = I18n::tr("This is not a GateBouncer rules file.");
        return false;
    }
    const QString kind = root.value("kind").toString();
    if (kind != QLatin1String("full") && kind != QLatin1String("share")) {
        error = I18n::tr("This is not a GateBouncer rules file.");
        return false;
    }
    const QJsonArray list = root.value("rules").toArray();
    if (list.size() > MaxRules) {
        error = I18n::tr("The file has more than %1 rules.").arg(MaxRules);
        return false;
    }
    out.full = kind == QLatin1String("full");
    out.exported = shownDate(root.value("exported").toString());
    out.app = root.value("app").toString().left(20);
    if (out.full && root.value("protection").isObject()) {
        const QJsonObject p = root.value("protection").toObject();
        if (p.value("ask").isBool() && p.value("localNetwork").isBool()) {
            out.hasProtection = true;
            out.ask = p.value("ask").toBool();
            out.localNetwork = p.value("localNetwork").toBool();
        }
    }
    QSet<QString> seen;
    for (const auto &value : list) {
        const QJsonObject o = value.toObject();
        const auto skip = [&](const QString &reason) { out.skipped.push_back({whatOf(o), reason}); };
        if (!value.isObject()) {
            out.skipped.push_back({I18n::tr("Unnamed entry"), I18n::tr("Not a rule GateBouncer knows")});
            continue;
        }
        Rule r;
        const QString action = o.value("action").toString();
        r.scope = o.value("scope").toString();
        const QStringList scopes{"path", "app", "publisher", "folder"};
        if ((action != QLatin1String("allow") && action != QLatin1String("block")) || !scopes.contains(r.scope)) {
            skip(I18n::tr("Not a rule GateBouncer knows"));
            continue;
        }
        r.allow = action == QLatin1String("allow");
        if ((o.contains("expires") && o.value("expires").toDouble() != 0) || o.value("temporary").toBool()) {
            skip(I18n::tr("Temporary rules are not imported"));
            continue;
        }
        r.path = native(o.value("path").toString());
        r.signer = o.value("signer").toString().trimmed();
        r.name = o.value("name").toString().trimmed();
        r.destination = o.value("destination").toString().trimmed().toLower();
        if (r.scope == QLatin1String("folder")) r.destination.clear();
        if (!out.full && (r.scope == QLatin1String("path") || r.scope == QLatin1String("folder"))) {
            skip(I18n::tr("A shared file carries no paths or folders"));
            continue;
        }
        bool ok = clean(r.path, 32767) && clean(r.signer, 512) && destinationOk(r.destination);
        if (r.scope == QLatin1String("path")) ok = ok && absolutePath(r.path) && !QFileInfo(r.path).fileName().isEmpty();
        if (r.scope == QLatin1String("app")) ok = ok && !r.signer.isEmpty() && !r.name.isEmpty() && fileNameOk(r.name);
        if (r.scope == QLatin1String("publisher")) ok = ok && !r.signer.isEmpty();
        if (r.scope == QLatin1String("folder")) ok = ok && absolutePath(r.path) && (r.name.isEmpty() || fileNameOk(r.name));
        if (!ok) {
            skip(I18n::tr("Invalid data"));
            continue;
        }
        // Como RULES: el nombre del exe de una regla por firma, en minúsculas.
        if (r.scope == QLatin1String("app")) r.name = r.name.toLower();
        if (r.scope != QLatin1String("app") && r.scope != QLatin1String("folder")) r.name.clear();
        if (r.scope == QLatin1String("app") || r.scope == QLatin1String("publisher")) r.path.clear();
        if (r.scope == QLatin1String("path") || r.scope == QLatin1String("folder")) r.signer.clear();
        if (r.scope == QLatin1String("publisher") && !FirewallClient::publisherRuleAllowed(r.signer)) {
            skip(I18n::tr("A Windows publisher cannot have a rule for all its apps"));
            continue;
        }
        const QString key = identity(r) + "|" + r.destination;
        if (seen.contains(key)) {
            skip(I18n::tr("Repeated in the file"));
            continue;
        }
        seen.insert(key);
        out.rules.push_back(r);
    }
    return true;
}

QString describe(const Rule &rule) { return FirewallClient::describe(asItem(rule)); }

QString title(const Rule &rule) { return title(asItem(rule)); }

QString title(const FirewallClient::RuleItem &rule) {
    if (rule.scope == QLatin1String("app")) return rule.name;
    if (rule.scope == QLatin1String("publisher")) return rule.signer;
    if (rule.scope == QLatin1String("folder")) return rule.name.isEmpty() ? FolderTrust::label(rule.path) : rule.name;
    return FirewallClient::fileName(rule.path);
}

void pathsToCheck(const File &file, QStringList &folders, QStringList &files) {
    for (const auto &r : file.rules) {
        if (r.scope == QLatin1String("folder")) folders << r.path;
        else if (r.scope == QLatin1String("path")) files << r.path;
    }
}

QVector<Planned> plan(const File &file, const QVector<FirewallClient::RuleItem> &current,
                      const QHash<QString, bool> &folderExists, const QHash<QString, bool> &fileExists) {
    // Tus reglas por identidad (sin las filas covered): para cada una, sus destinos.
    QHash<QString, QVector<const FirewallClient::RuleItem *>> mine;
    for (const auto &r : current)
        if (r.scope != QLatin1String("covered")) mine[identity(r)].push_back(&r);
    QVector<Planned> out;
    out.reserve(file.rules.size());
    for (const auto &r : file.rules) {
        Planned p;
        p.rule = r;
        if (r.scope == QLatin1String("folder") && !folderExists.value(lower(r.path), false)) {
            p.state = State::Skipped;
            p.reason = I18n::tr("Folder not found on this PC");
            out.push_back(p);
            continue;
        }
        if (r.scope == QLatin1String("path") && !fileExists.value(lower(r.path), false))
            p.note = I18n::tr("Not on this PC yet");
        const auto same = mine.value(identity(r));
        const FirewallClient::RuleItem *exact = nullptr;
        int perServer = 0;
        const FirewallClient::RuleItem *whole = nullptr;
        for (const auto *m : same) {
            if (lower(m->destination) == r.destination) exact = m;
            if (m->destination.isEmpty()) whole = m;
            else ++perServer;
        }
        if (exact) {
            if (exact->allow == r.allow && exact->expires == 0) {
                p.state = State::Same;
            } else {
                p.state = State::Conflict;
                if (exact->expires != 0)
                    p.yours = exact->allow ? I18n::tr("Yours: Allow, temporary") : I18n::tr("Yours: Block, temporary");
                else p.yours = exact->allow ? I18n::tr("Yours: Allow") : I18n::tr("Yours: Block");
            }
        } else if (r.scope != QLatin1String("folder") && r.destination.isEmpty() && perServer > 0) {
            // La app entera reemplazaría tus reglas por servidor.
            p.state = State::Conflict;
            p.yours = perServer == 1 ? I18n::tr("Yours: 1 rule for a single server")
                                     : I18n::tr("Yours: %1 rules for single servers").arg(perServer);
        } else if (r.scope != QLatin1String("folder") && !r.destination.isEmpty() && whole) {
            // Una regla por servidor pasa la app a modo por destino: reemplazaría tu regla de la app entera.
            p.state = State::Conflict;
            p.yours = whole->allow ? I18n::tr("Yours: Allow for the whole app") : I18n::tr("Yours: Block for the whole app");
        }
        out.push_back(p);
    }
    return out;
}

QString commandFor(const Rule &rule, bool replace) {
    if (rule.scope == QLatin1String("folder"))
        return QString("FOLDER\t%1\t%2\t%3").arg(rule.allow ? "allow" : "block", rule.path,
                                                rule.name.isEmpty() ? QStringLiteral("*") : rule.name);
    return QStringList{"IMPORT", rule.allow ? "allow" : "block", rule.scope, rule.signer, rule.name, rule.path,
                       rule.destination, replace ? "replace" : "keep"}
        .join('\t');
}

bool isExists(const QString &error) { return error.trimmed().startsWith(QLatin1String("exists")); }
bool isConflict(const QString &error) { return error.trimmed().startsWith(QLatin1String("conflict")); }

void cleanupPaths(const QVector<FirewallClient::RuleItem> &rules, QStringList &files, QStringList &folders) {
    for (const auto &r : rules) {
        if (r.expires != 0 || r.path.isEmpty()) continue;
        if (r.scope == QLatin1String("path")) files << r.path;
        else if (r.scope == QLatin1String("folder")) folders << r.path;
    }
}

bool installerLike(const QString &path, const QString &name) {
    const QString p = lower(native(path));
    if (p.contains(QLatin1String("\\temp\\")) || p.contains(QLatin1String("\\tmp\\")) ||
        p.contains(QLatin1String("\\downloads\\")))
        return true;
    const QString n = lower(name.isEmpty() ? FirewallClient::fileName(path) : name);
    for (const char *word : {"setup", "install", "update", "uninst"})
        if (n.contains(QLatin1String(word))) return true;
    return false;
}

QVector<Candidate> cleanup(const QVector<FirewallClient::RuleItem> &rules, const QHash<QString, qint64> &lastUse,
                           qint64 since, qint64 now, const QHash<QString, bool> &exists) {
    QVector<Candidate> out;
    for (const auto &r : rules) {
        if (r.scope == QLatin1String("covered") || r.expires != 0) continue;
        Candidate c;
        c.rule = r;
        c.lastUse = lastUse.value(lower(r.id), 0);
        const auto found = exists.constFind(lower(r.path));
        const bool missing = !r.path.isEmpty() && found != exists.constEnd() && !found.value();
        if (r.scope == QLatin1String("path") && missing) {
            c.group = MissingProgram;
            out.push_back(c);
            continue;
        }
        if (r.scope == QLatin1String("folder") && missing) {
            c.group = MissingFolder;
            out.push_back(c);
            continue;
        }
        // Antes de que el motor anote uso no se sabe nada: el plazo corre desde since (o desde que se creó la regla).
        if (since <= 0) continue;
        const qint64 idle = now - qMax(c.lastUse, qMax(since, r.created));
        const bool installer = (r.scope == QLatin1String("path") || r.scope == QLatin1String("app")) &&
                               installerLike(r.path, r.scope == QLatin1String("app") ? r.name : QString());
        if (installer && idle > InstallerDays * 86400) {
            c.group = Installer;
            out.push_back(c);
        } else if (idle > UnusedDays * 86400) {
            c.group = Unused;
            out.push_back(c);
        }
    }
    return out;
}

QHash<QString, bool> checkPaths(const QStringList &files, const QStringList &folders) {
    QHash<QString, bool> out;
    QHash<QString, bool> roots; // unidad o recurso compartido -> responde
    const auto rootOf = [](const QString &p) -> QString {
        const QString n = native(p);
        if (n.startsWith(QLatin1String("\\\\"))) {
            const QStringList parts = n.mid(2).split('\\', Qt::SkipEmptyParts);
            return parts.size() >= 2 ? "\\\\" + parts[0] + "\\" + parts[1] + "\\" : QString();
        }
        return n.size() >= 3 && n[1] == ':' ? n.left(3) : QString();
    };
    const auto reachable = [&](const QString &p) {
        const QString root = rootOf(p);
        if (root.isEmpty()) return false;
        const auto it = roots.constFind(lower(root));
        if (it != roots.constEnd()) return it.value();
        const bool ok = QFileInfo(root).isDir();
        roots.insert(lower(root), ok);
        return ok;
    };
    // Una unidad desconectada o un servidor que no responde no dicen nada del archivo: esa ruta no figura.
    for (const auto &f : files)
        if (reachable(f)) out.insert(lower(f), QFileInfo(f).isFile());
    for (const auto &d : folders)
        if (reachable(d)) out.insert(lower(d), QFileInfo(d).isDir());
    return out;
}

} // namespace Gate::RulesTransfer
