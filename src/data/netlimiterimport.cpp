#include "netlimiterimport.h"
#include <QCryptographicHash>
#include <QSet>
#include <QUuid>
#include <QXmlStreamReader>
#include <algorithm>

namespace Gate::Data {
namespace {
QString childText(const XmlNode &node, const QString &name) {
    for (const auto &child : node.children)
        if (child.name == name && child.nameSpace.isEmpty() && child.children.isEmpty())
            return child.text.trimmed();
    return {};
}
class StructuralReader {
  public:
    explicit StructuralReader(const QByteArray &bytes, const ImportLimits &limits)
        : xml(bytes), limits(limits) {
        xml.setNamespaceProcessing(true);
        xml.setEntityExpansionLimit(64);
    }
    bool parse(XmlNode &root) {
        bool found = false;
        while (!xml.atEnd()) {
            const auto token = xml.readNext();
            if (forbidden(token)) return false;
            if (token == QXmlStreamReader::StartElement) {
                if (found || !node(root, 1)) return false;
                found = true;
            }
        }
        return found && !xml.hasError();
    }
    QXmlStreamReader xml;
  private:
    const ImportLimits &limits;
    int elementCount = 0;
    bool fail(const char *message) {
        xml.raiseError(QString::fromLatin1(message));
        return false;
    }
    bool forbidden(QXmlStreamReader::TokenType token) {
        if (token == QXmlStreamReader::DTD || token == QXmlStreamReader::EntityReference) {
            fail("DTD and unresolved entities are not supported");
            return true;
        }
        return false;
    }
    bool node(XmlNode &out, int depth) {
        if (depth > limits.depth || ++elementCount > limits.elements)
            return fail("Depth or element limit exceeded");
        if (xml.attributes().size() > limits.attributes || xml.name().size() > limits.text ||
            xml.namespaceUri().size() > limits.text)
            return fail("Attribute or name limit exceeded");
        out.name = xml.name().toString();
        out.nameSpace = xml.namespaceUri().toString();
        if (!out.nameSpace.isEmpty())
            return fail("External namespace has not been validated");
        for (const auto &attribute : xml.attributes()) {
            if (!attribute.namespaceUri().isEmpty())
                return fail("External attribute namespace has not been validated");
            if (attribute.value().size() > limits.text ||
                attribute.qualifiedName().size() > limits.text)
                return fail("Attribute limit exceeded");
            out.attributes.insert(attribute.qualifiedName().toString(), attribute.value().toString());
        }
        while (!xml.atEnd()) {
            const auto token = xml.readNext();
            if (forbidden(token)) return false;
            if (token == QXmlStreamReader::EndElement) return true;
            if (token == QXmlStreamReader::Characters) {
                if (out.text.size() + xml.text().size() > limits.text)
                    return fail("Text limit exceeded");
                out.text += xml.text();
            } else if (token == QXmlStreamReader::StartElement) {
                XmlNode child;
                if (!node(child, depth + 1)) return false;
                out.children.push_back(std::move(child));
            }
        }
        return false;
    }
};
bool dependencyBounds(const XmlNode &node, const ImportLimits &limits) {
    if ((node.name == "FunctionList" && node.children.size() > limits.functions) ||
        (node.name == "Values" && node.children.size() > limits.values))
        return false;
    for (const auto &child : node.children)
        if (!dependencyBounds(child, limits)) return false;
    return true;
}
} // namespace

ImportReport NetLimiterImport::analyze(QIODevice &input, const ImportLimits &limits) {
    ImportReport report;
    if (!input.isReadable() || limits.bytes <= 0 || limits.bytes > 8 * 1024 * 1024 ||
        limits.depth <= 0 || limits.depth > 32 || limits.elements <= 0 ||
        limits.elements > 200000 || limits.attributes < 0 || limits.attributes > 32 ||
        limits.text <= 0 || limits.text > 32768 || limits.rules < 0 || limits.rules > 10000 ||
        limits.dependencies < 0 || limits.dependencies > 20000 || limits.functions < 0 ||
        limits.functions > 64 || limits.values < 0 || limits.values > 256) {
        report.error = "Input is not readable or limits are invalid";
        return report;
    }
    // Leer una unidad extra detecta exceso sin confiar en size() de un dispositivo secuencial.
    QByteArray bytes;
    while (bytes.size() <= limits.bytes && !input.atEnd()) {
        const auto chunk = input.read(std::min<qint64>(65536, limits.bytes + 1 - bytes.size()));
        if (chunk.isEmpty()) {
            report.error = "Could not complete the read";
            return report;
        }
        bytes += chunk;
    }
    if (bytes.size() > limits.bytes) {
        report.error = "Byte limit exceeded";
        return report;
    }
    StructuralReader reader(bytes, limits);
    XmlNode root;
    if (!reader.parse(root)) {
        report.error = "XML rejected";
        report.errorLine = reader.xml.lineNumber();
        report.errorColumn = reader.xml.columnNumber();
        return report;
    }
    if (root.name != "NLSvcSettings") {
        report.error = "Configuration root is not recognized";
        return report;
    }
    QVector<XmlNode> rules;
    for (const auto &section : root.children) {
        if (section.name == "Rules") rules += section.children;
        else if (section.name == "Filters") report.filters += section.children;
        else if (section.name == "AppInfos") report.identities += section.children;
    }
    if (rules.size() > limits.rules ||
        report.filters.size() + report.identities.size() > limits.dependencies ||
        !dependencyBounds(root, limits)) {
        ImportReport rejected;
        rejected.error = "Rule or dependency limit exceeded";
        return rejected;
    }
    report.digest = QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex());
    report.sourceVersion = childText(root, "Version");
    report.diagnostics = {"Structure recognized; rule mapping has not been validated",
                          "No rules are applied and no history is imported"};
    QSet<QString> ids;
    for (const auto &node : rules) {
        Candidate candidate;
        candidate.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
        candidate.source = node;
        candidate.sourceId = childText(node, "Id");
        candidate.sourceType = node.attributes.value("type");
        candidate.status = candidate.sourceType == "fwRule" ? CandidateStatus::NeedsReview
                                                            : CandidateStatus::Unsupported;
        auto action = childText(node, "action");
        candidate.action = action == "Deny" ? std::optional<Action>(Action::Block) : readAction(action);
        candidate.direction = readDirection(childText(node, "Dir"));
        const auto enabled = childText(node, "IsEnabled");
        if (enabled == "true") candidate.sourceEnabled = true;
        else if (enabled == "false") candidate.sourceEnabled = false;
        const auto weight = childText(node, "Weight");
        bool weightOk = false;
        const auto number = weight.toLongLong(&weightOk);
        if (weightOk) candidate.sourceWeight = number;
        candidate.diagnostics = {"Inactive candidate; source semantics have not been validated"};
        if (candidate.status == CandidateStatus::Unsupported)
            candidate.diagnostics.push_back("Rule type is unsupported or outside the current scope");
        if (candidate.sourceId.isEmpty()) candidate.diagnostics.push_back("Source identifier has not been established");
        else if (ids.contains(candidate.sourceId))
            report.diagnostics.push_back("Duplicate source identifier; batch equivalence has not been established");
        else ids.insert(candidate.sourceId);
        if (!candidate.action || candidate.direction == Direction::Unknown || !candidate.sourceEnabled)
            candidate.diagnostics.push_back("Source properties are incomplete or unknown");
        report.candidates.push_back(std::move(candidate));
    }
    report.accepted = true;
    return report;
}
} // namespace Gate::Data
