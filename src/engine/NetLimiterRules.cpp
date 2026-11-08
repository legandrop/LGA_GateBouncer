#include "NetLimiterRules.h"
#include "i18n.h"
#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QSet>
#include <QXmlStreamReader>
#include <memory>
#include <windows.h>

namespace Gate {
namespace {
constexpr qint64 SizeLimit = 32 * 1024 * 1024;
constexpr int DepthLimit = 64;

// NetLimiter guarda a veces la ruta corta (C:\PROGRA~2\...\VCTIP.EXE); el motor recibe siempre la larga, así que
// una regla con la corta nunca coincide. Si el archivo existe se usa su forma larga.
QString longPath(const QString &path) {
    const std::wstring shortPath = QDir::toNativeSeparators(path).toStdWString();
    wchar_t buffer[2048];
    const DWORD n = GetLongPathNameW(shortPath.c_str(), buffer, DWORD(std::size(buffer)));
    return n > 0 && n < std::size(buffer) ? QString::fromWCharArray(buffer, int(n)) : path;
}

struct Node {
    QString name, type, text;
    std::vector<std::unique_ptr<Node>> children;
    const Node *child(const QString &n) const {
        for (const auto &c : children)
            if (c->name == n) return c.get();
        return nullptr;
    }
    QString value(const QString &n) const {
        const Node *c = child(n);
        return c ? c->text.trimmed() : QString();
    }
};

// Árbol mínimo por nombre local: los prefijos de espacio de nombres de NetLimiter varían entre versiones.
std::unique_ptr<Node> parse(QIODevice &input, QString &error) {
    QXmlStreamReader xml(&input);
    auto root = std::make_unique<Node>();
    std::vector<Node *> stack{root.get()};
    while (!xml.atEnd()) {
        xml.readNext();
        if (xml.isStartElement()) {
            if (int(stack.size()) > DepthLimit) {
                error = I18n::tr("The file is nested too deeply to be a NetLimiter settings file.");
                return nullptr;
            }
            auto node = std::make_unique<Node>();
            node->name = xml.name().toString();
            for (const auto &a : xml.attributes())
                if (a.name() == QLatin1String("type")) node->type = a.value().toString().section(':', -1);
            Node *raw = node.get();
            stack.back()->children.push_back(std::move(node));
            stack.push_back(raw);
        } else if (xml.isEndElement()) {
            stack.pop_back();
        } else if (xml.isCharacters() && !xml.isWhitespace()) {
            stack.back()->text += xml.text();
        }
    }
    if (xml.hasError()) {
        error = I18n::tr("This is not a valid XML file (line %1): %2").arg(xml.lineNumber()).arg(xml.errorString());
        return nullptr;
    }
    return root;
}

const Node *find(const Node *node, const QString &name) {
    if (!node) return nullptr;
    if (node->name == name) return node;
    for (const auto &c : node->children)
        if (const Node *hit = find(c.get(), name)) return hit;
    return nullptr;
}
} // namespace

QString NetLimiterRules::defaultFolder() {
    const QString folder = qEnvironmentVariable("ProgramData") + "\\Locktime\\NetLimiter";
    return QFileInfo(folder).isDir() ? QDir::fromNativeSeparators(folder) : QString();
}

QVector<NetLimiterRule> NetLimiterRules::read(QIODevice &input, QString &error) {
    QVector<NetLimiterRule> out;
    if (input.size() > SizeLimit) {
        error = I18n::tr("The file is too large to be a NetLimiter settings file.");
        return out;
    }
    const auto root = parse(input, error);
    if (!root) return out;
    const Node *filters = find(root.get(), "Filters");
    const Node *rules = find(root.get(), "Rules");
    if (!filters || !rules) {
        error = I18n::tr("No NetLimiter filters and rules were found in this file. Choose nl_settings.xml from NetLimiter.");
        return out;
    }
    // Filtro -> rutas, o el motivo por el que no es «sólo esta app».
    struct Filter {
        QString name;
        QStringList paths;
        QString problem;
    };
    QHash<QString, Filter> byId;
    for (const auto &f : filters->children) {
        if (f->name != "filter") continue;
        Filter filter;
        filter.name = f->value("Name");
        const Node *functions = f->child("FunctionList");
        const Node *base = f->child("BaseFilters");
        if (base && !base->children.empty()) filter.problem = I18n::tr("Combines other NetLimiter filters");
        else if (!functions || functions->children.empty()) filter.problem = I18n::tr("Filter without conditions");
        else if (functions->children.size() > 1)
            filter.problem = I18n::tr("Also limited by destination, port or other conditions");
        else {
            const Node *fn = functions->children.front().get();
            const QString match = fn->value("match").toLower();
            if (fn->type != "FFAppIdEqual") filter.problem = I18n::tr("Not an application filter");
            else if (!match.isEmpty() && match != "false") filter.problem = I18n::tr("Inverted application filter");
            else if (const Node *values = fn->child("Values"))
                for (const auto &v : values->children)
                    if (!v->value("Path").isEmpty()) filter.paths << QDir::toNativeSeparators(v->value("Path"));
            if (filter.problem.isEmpty() && filter.paths.isEmpty())
                filter.problem = I18n::tr("Application not identified by path");
        }
        byId.insert(f->value("Id"), filter);
    }
    QHash<QString, int> decided; // ruta en minúsculas -> índice en out, para detectar Allow y Deny a la vez
    QSet<QString> conflicted;    // rutas con Allow y Deny: quedan fuera aunque aparezcan más reglas suyas
    const QString Conflict = I18n::tr("Both Allow and Deny rules exist for this application");
    for (const auto &r : rules->children) {
        if (r->name != "rule" || r->type != "fwRule") continue;
        const auto filter = byId.constFind(r->value("FilterId"));
        const QString action = r->value("action"), direction = r->value("Dir");
        const bool enabled = r->value("IsEnabled").compare("true", Qt::CaseInsensitive) == 0;
        QString reason;
        if (filter == byId.constEnd()) reason = I18n::tr("Its filter is missing from the file");
        else if (!filter->problem.isEmpty()) reason = filter->problem;
        else if (!enabled) reason = I18n::tr("Disabled in NetLimiter");
        else if (direction != "Out" && direction != "Both") reason = I18n::tr("Incoming connections only");
        else if (action == "Ask") reason = I18n::tr("Ask rule: GateBouncer already asks");
        else if (action != "Allow" && action != "Deny" && action != "Block") reason = I18n::tr("Unknown action");
        const QStringList paths = filter != byId.constEnd() && !filter->paths.isEmpty() ? filter->paths : QStringList{QString()};
        for (const QString &path : paths) {
            NetLimiterRule item;
            item.path = longPath(path);
            item.ruleName = filter != byId.constEnd() ? filter->name : QString();
            item.action = action == "Block" ? QStringLiteral("Deny") : action;
            item.allow = action == "Allow";
            item.reason = reason;
            if (reason.isEmpty() && !QFileInfo::exists(item.path)) item.reason = I18n::tr("File not found on this PC");
            item.importable = item.reason.isEmpty();
            if (item.importable) {
                const QString key = item.path.toLower();
                const auto seen = decided.constFind(key);
                if (conflicted.contains(key)) {
                    // Ya hubo Allow y Deny para esta app: ninguna regla posterior suya se importa.
                    item.importable = false;
                    item.reason = Conflict;
                } else if (seen != decided.constEnd() && out[*seen].allow != item.allow) {
                    // Allow y Deny para la misma app: el resultado dependería de los pesos de NetLimiter. No se adivina.
                    conflicted.insert(key);
                    out[*seen].importable = false;
                    out[*seen].reason = item.reason = Conflict;
                    item.importable = false;
                } else if (seen != decided.constEnd()) {
                    continue; // la misma regla repetida
                } else {
                    decided.insert(key, int(out.size()));
                }
            }
            out.push_back(item);
        }
    }
    return out;
}

} // namespace Gate
