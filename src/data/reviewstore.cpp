#include "reviewstore.h"
#include "qnamereviewcodec.h"
#include "activityhistory.h"
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QFileInfo>
#include <QSet>
#include <QUuid>
#include <limits>
#include <algorithm>

namespace Gate::Data {
namespace {
constexpr qint64 storeByteLimit = 32 * 1024 * 1024;
QString dateText(const QDateTime &date) { return date.toUTC().toString(Qt::ISODateWithMs); }
QDateTime dateRead(const QJsonValue &value) {
    const auto date = QDateTime::fromString(value.toString(), Qt::ISODateWithMs);
    return value.isString() && date.isValid() && date.offsetFromUtc() == 0 ? date : QDateTime{};
}
StoreResult failure(StoreStatus status, const char *error) {
    return {status, QString::fromLatin1(error), std::nullopt};
}
QJsonArray stringArray(const QVector<QString> &strings) {
    QJsonArray array;
    for (const auto &string : strings) array.push_back(string);
    return array;
}
bool stringsRead(const QJsonValue &value, QVector<QString> &strings) {
    if (!value.isArray() || value.toArray().size() > 20000) return false;
    for (const auto &entry : value.toArray()) {
        if (!entry.isString()) return false;
        strings.push_back(entry.toString());
    }
    return true;
}
bool stringFields(const QJsonObject &object, std::initializer_list<const char *> names) {
    for (const auto name : names) if (!object[name].isString()) return false;
    return true;
}
QJsonObject nodeJson(const XmlNode &node) {
    QJsonObject attributes;
    for (auto it = node.attributes.begin(); it != node.attributes.end(); ++it)
        attributes.insert(it.key(), it.value());
    QJsonArray children;
    for (const auto &child : node.children) children.push_back(nodeJson(child));
    return {{"name", node.name}, {"namespace", node.nameSpace}, {"text", node.text},
            {"attributes", attributes}, {"children", children}};
}
bool nodeRead(const QJsonValue &value, XmlNode &node, int depth, int &count) {
    if (!value.isObject() || depth > 32 || ++count > 200000) return false;
    const auto object = value.toObject();
    if (!object["name"].isString() || !object["namespace"].isString() ||
        !object["text"].isString() || !object["attributes"].isObject() ||
        object["attributes"].toObject().size() > 32 || !object["children"].isArray()) return false;
    node.name = object["name"].toString();
    node.nameSpace = object["namespace"].toString();
    node.text = object["text"].toString();
    const auto attributes = object["attributes"].toObject();
    for (auto it = attributes.begin(); it != attributes.end(); ++it) {
        if (!it.value().isString()) return false;
        node.attributes.insert(it.key(), it.value().toString());
    }
    for (const auto &child : object["children"].toArray()) {
        XmlNode parsed;
        if (!nodeRead(child, parsed, depth + 1, count)) return false;
        node.children.push_back(std::move(parsed));
    }
    return true;
}
QJsonObject factJson(const EventFact &fact) {
    return {{"at", fact.atUtc.isValid() ? QJsonValue(dateText(fact.atUtc)) : QJsonValue(QJsonValue::Null)}, {"source", fact.sourceId},
            {"epoch", fact.sourceEpoch}, {"sequence", fact.sequence}};
}
bool factRead(const QJsonValue &value, EventFact &fact, bool unknown = false) {
    if (!value.isObject()) return false;
    const auto object = value.toObject();
    fact = {dateRead(object["at"]), object["source"].toString(),
            object["epoch"].toString(), object["sequence"].toString()};
    return stringFields(object, {"source", "epoch", "sequence"}) &&
           (fact.atUtc.isValid() || (unknown && object["at"].isNull())) && !fact.sourceId.isEmpty() && !fact.sourceEpoch.isEmpty() &&
           decimalUnsigned(fact.sequence) && fact.sequence != "0";
}
QJsonValue optionalFact(const std::optional<EventFact> &fact) {
    return fact ? QJsonValue(factJson(*fact)) : QJsonValue(QJsonValue::Null);
}
bool optionalFactRead(const QJsonValue &value, std::optional<EventFact> &fact, bool unknown = false) {
    if (value.isNull()) return true;
    EventFact parsed;
    if (!factRead(value, parsed, unknown)) return false;
    fact = parsed;
    return true;
}
QJsonValue optionalAction(const std::optional<Action> &action) {
    return action ? QJsonValue(actionName(*action)) : QJsonValue(QJsonValue::Null);
}
bool optionalActionRead(const QJsonValue &value, std::optional<Action> &action) {
    if (value.isNull()) return true;
    action = readAction(value.toString());
    return action.has_value();
}
QJsonObject reportJson(const ImportReport &report) {
    QJsonArray candidates, filters, identities;
    for (const auto &candidate : report.candidates)
        candidates.push_back(QJsonObject{{"id", candidate.id}, {"sourceId", candidate.sourceId},
            {"sourceType", candidate.sourceType}, {"source", nodeJson(candidate.source)},
            {"status", candidate.status == CandidateStatus::NeedsReview ? "NeedsReview" : "Unsupported"},
            {"activation", "Inactive"}, {"diagnostics", stringArray(candidate.diagnostics)},
            {"action", optionalAction(candidate.action)}, {"reviewAction", optionalAction(candidate.reviewAction)},
            {"direction", directionName(candidate.direction)}, {"reviewed", candidate.reviewed},
            {"sourceEnabled", candidate.sourceEnabled ? QJsonValue(*candidate.sourceEnabled) : QJsonValue(QJsonValue::Null)},
            {"sourceWeight", candidate.sourceWeight ? QJsonValue(QString::number(*candidate.sourceWeight)) : QJsonValue(QJsonValue::Null)}});
    for (const auto &filter : report.filters) filters.push_back(nodeJson(filter));
    for (const auto &identity : report.identities) identities.push_back(nodeJson(identity));
    return {{"accepted", report.accepted}, {"digest", report.digest}, {"sourceVersion", report.sourceVersion},
            {"error", report.error}, {"errorLine", QString::number(report.errorLine)},
            {"errorColumn", QString::number(report.errorColumn)}, {"diagnostics", stringArray(report.diagnostics)},
            {"candidates", candidates}, {"filters", filters}, {"identities", identities}};
}
bool reportRead(const QJsonValue &value, ImportReport &report) {
    if (!value.isObject()) return false;
    const auto object = value.toObject();
    if (!stringFields(object, {"digest", "sourceVersion", "error", "errorLine", "errorColumn"}) ||
        !object["accepted"].isBool() || !object["candidates"].isArray() ||
        object["candidates"].toArray().size() > 10000 || !object["filters"].isArray() ||
        !object["identities"].isArray() || object["filters"].toArray().size() +
        object["identities"].toArray().size() > 20000) return false;
    report.accepted = object["accepted"].toBool();
    report.digest = object["digest"].toString();
    report.sourceVersion = object["sourceVersion"].toString();
    report.error = object["error"].toString();
    quint64 line = 0, column = 0;
    if (!decimalUnsigned(object["errorLine"].toString(), &line) ||
        !decimalUnsigned(object["errorColumn"].toString(), &column) ||
        line > quint64(std::numeric_limits<qint64>::max()) || column > quint64(std::numeric_limits<qint64>::max()) ||
        !stringsRead(object["diagnostics"], report.diagnostics)) return false;
    report.errorLine = qint64(line);
    report.errorColumn = qint64(column);
    if (report.accepted) {
        if (report.digest.size() != 64) return false;
        for (const auto ch : report.digest)
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
    }
    int nodes = 0;
    QSet<QString> ids;
    for (const auto &entry : object["candidates"].toArray()) {
        if (!entry.isObject()) return false;
        const auto row = entry.toObject();
        Candidate candidate;
        candidate.id = row["id"].toString();
        if (!stringFields(row, {"id", "sourceId", "sourceType", "status", "activation", "direction"}) ||
            QUuid(candidate.id).isNull() || QUuid(candidate.id).toString(QUuid::WithoutBraces) != candidate.id ||
            ids.contains(candidate.id) || row["activation"] != "Inactive" ||
            !row["reviewed"].isBool()) return false;
        ids.insert(candidate.id);
        candidate.sourceId = row["sourceId"].toString();
        candidate.sourceType = row["sourceType"].toString();
        if (row["status"] == "NeedsReview") candidate.status = CandidateStatus::NeedsReview;
        else if (row["status"] == "Unsupported") candidate.status = CandidateStatus::Unsupported;
        else return false;
        if (!nodeRead(row["source"], candidate.source, 1, nodes) ||
            !stringsRead(row["diagnostics"], candidate.diagnostics) ||
            !optionalActionRead(row["action"], candidate.action) ||
            !optionalActionRead(row["reviewAction"], candidate.reviewAction)) return false;
        candidate.direction = readDirection(row["direction"].toString());
        if (candidate.direction == Direction::Unknown && row["direction"] != "Unknown") return false;
        candidate.reviewed = row["reviewed"].toBool();
        if (!row["sourceEnabled"].isNull()) {
            if (!row["sourceEnabled"].isBool()) return false;
            candidate.sourceEnabled = row["sourceEnabled"].toBool();
        }
        if (!row["sourceWeight"].isNull()) {
            bool ok = false;
            const auto weight = row["sourceWeight"].toString().toLongLong(&ok);
            if (!ok || QString::number(weight) != row["sourceWeight"].toString()) return false;
            candidate.sourceWeight = weight;
        }
        report.candidates.push_back(std::move(candidate));
    }
    for (const auto key : {"filters", "identities"})
        for (const auto &entry : object[key].toArray()) {
            XmlNode parsed;
            if (!nodeRead(entry, parsed, 1, nodes)) return false;
            (QString::fromLatin1(key) == "filters" ? report.filters : report.identities).push_back(std::move(parsed));
        }
    return report.accepted || (report.candidates.isEmpty() && report.filters.isEmpty() && report.identities.isEmpty());
}
QJsonObject bindingJson(const NativeSourceBinding &b) {
    return {{"service", b.serviceEpoch}, {"boot", b.boot}, {"engine", b.engineContext},
        {"source", b.sourceEpoch}, {"generation", QString::number(b.generation)}, {"profile", QString::number(b.profile)}};
}
bool bindingRead(const QJsonValue &value, NativeSourceBinding &b) {
    if (!value.isObject()) return false;
    const auto o = value.toObject();
    b.serviceEpoch = o["service"].toString(); b.boot = o["boot"].toString();
    b.engineContext = o["engine"].toString(); b.sourceEpoch = o["source"].toString();
    return o.size() == 6 && decimalUnsigned(o["generation"].toString(), &b.generation) &&
        decimalUnsigned(o["profile"].toString(), &b.profile) && validNativeBinding(b);
}
QJsonObject evidenceJson(const NativeEvidence &n) {
    QJsonObject o{{"connection", n.connection}, {"observed", n.observed}, {"binding", n.captureBinding}, {"command", n.command},
        {"revision", QString::number(n.observedRevision)}, {"unixns", QString::number(n.unixNanoseconds)},
        {"presence", QString::number(n.presence)}, {"attempt", QString::number(n.attemptSequence)},
        {"effective", QString::number(n.effectiveRevision)}, {"source", int(n.source)},
        {"direction", int(n.direction)}, {"protocol", int(n.protocol)}, {"scope", int(n.scope)},
        {"durable", n.durable}, {"effect", n.currentEffect}, {"externalPartial", n.externalPartial}};
    if (n.routeMask == 7) {
        o["routeMask"] = int(n.routeMask); o["packetCount"] = QString::number(n.packetCount);
        o["packetDirection"] = int(n.packetDirection);
    }
    return o;
}
bool evidenceRead(const QJsonValue &value, NativeEvidence &n) {
    if (!value.isObject()) return false;
    const auto o = value.toObject();
    if ((o.size() != 16 && o.size() != 19) || !stringFields(o, {"connection", "observed", "binding", "command"})) return false;
    if (o.size() == 19) {
        if (!o["routeMask"].isDouble() || o["routeMask"].toDouble() != o["routeMask"].toInt() ||
            (o["routeMask"].toInt() != 3 && o["routeMask"].toInt() != 7) ||
            !decimalUnsigned(o["packetCount"].toString(), &n.packetCount) ||
            !o["packetDirection"].isDouble() || o["packetDirection"].toDouble() != o["packetDirection"].toInt() ||
            o["packetDirection"].toInt() < 0 || o["packetDirection"].toInt() > 2) return false;
        n.routeMask = quint8(o["routeMask"].toInt()); n.packetDirection = quint8(o["packetDirection"].toInt());
    } else if (o.contains("routeMask") || o.contains("packetCount") || o.contains("packetDirection")) return false;
    n.connection = o["connection"].toString(); n.observed = o["observed"].toString();
    n.captureBinding = o["binding"].toString(); n.command = o["command"].toString();
    for (const auto &field : {std::pair<const char *, quint64 *>{"revision", &n.observedRevision},
        {"unixns", &n.unixNanoseconds}, {"presence", &n.presence}, {"attempt", &n.attemptSequence}, {"effective", &n.effectiveRevision}})
        if (!decimalUnsigned(o[field.first].toString(), field.second)) return false;
    for (const auto &field : {std::pair<const char *, quint8 *>{"source", &n.source},
        {"direction", &n.direction}, {"protocol", &n.protocol}, {"scope", &n.scope}}) {
        const auto v = o[field.first];
        if (!v.isDouble() || v.toDouble() != v.toInt() || v.toInt() < 0 || v.toInt() > 255) return false;
        *field.second = quint8(v.toInt());
    }
    for (const auto &field : {std::pair<const char *, bool *>{"durable", &n.durable},
        {"effect", &n.currentEffect}, {"externalPartial", &n.externalPartial}}) {
        if (!o[field.first].isBool()) return false;
        *field.second = o[field.first].toBool();
    }
    return true;
}
QJsonObject eventJson(const ActivityEvent &event) {
        QJsonValue instance(QJsonValue::Null);
        if (event.instance) instance = QJsonObject{{"epoch", event.instance->sourceEpoch},
            {"pid", QString::number(event.instance->pid)}, {"creation", QString::number(event.instance->creationFiletime)}};
        QJsonObject o{{"source", event.sourceId}, {"epoch", event.sourceEpoch},
            {"sequence", event.sequence}, {"kind", int(event.kind)}, {"observed", event.observedAtUtc.isValid() ? QJsonValue(dateText(event.observedAtUtc)) : QJsonValue(QJsonValue::Null)},
            {"received", dateText(event.receivedAtUtc)}, {"subject", event.subjectId}, {"request", event.requestId},
            {"flow", event.flowId}, {"instance", instance}, {"action", optionalAction(event.action)},
            {"rule", event.winningRuleId}, {"ruleRevision", event.winningRuleRevision},
            {"endpoint", event.endpoint}, {"protocol", event.protocol}, {"synthetic", event.synthetic},
            {"bytes", event.bytes ? QJsonValue(QString::number(*event.bytes)) : QJsonValue(QJsonValue::Null)}};
        if (event.native) o["native"] = evidenceJson(*event.native);
        return o;
}
QJsonObject historyJson(const HistoryState &state) {
    QJsonArray events, coverage;
    QJsonObject subjects, hits;
    for (const auto &event : state.events) events.push_back(eventJson(event));
    for (auto it = state.subjects.begin(); it != state.subjects.end(); ++it)
        subjects.insert(it.key(), QJsonObject{{"attempt", optionalFact(it->lastAttempt)},
            {"authorized", optionalFact(it->lastAuthorized)}, {"traffic", optionalFact(it->lastTraffic)}});
    for (auto it = state.ruleHits.begin(); it != state.ruleHits.end(); ++it) hits.insert(it.key(), factJson(it.value()));
    for (const auto &source : state.coverage) {
        QJsonArray gaps;
        for (const auto &gap : source.gaps) {
            QJsonObject g{{"at", dateText(gap.atUtc)}, {"reason", gap.reason}, {"lost", QString::number(gap.lost)}};
            if (source.native) {
                g["lostKnown"] = gap.lostKnown; g["remote"] = gap.remote;
                g["after"] = QString::number(gap.after); g["resync"] = QString::number(gap.resync);
                g["revision"] = QString::number(gap.revision); g["nativeReason"] = int(gap.nativeReason);
            }
            gaps.push_back(g);
        }
        QJsonObject c{{"source", source.sourceId}, {"epoch", source.sourceEpoch},
            {"scope", source.declaredScope}, {"synthetic", source.synthetic}, {"status", int(source.status)},
            {"lastSequence", QString::number(source.lastSequence)},
            {"lastObserved", source.lastObservedUtc.isValid() ? QJsonValue(dateText(source.lastObservedUtc)) : QJsonValue(QJsonValue::Null)},
            {"since", dateText(source.sinceUtc)}, {"checkpoint", source.checkpointUtc.isValid() ?
             QJsonValue(dateText(source.checkpointUtc)) : QJsonValue(QJsonValue::Null)}, {"gaps", gaps}};
        if (source.native) c["native"] = bindingJson(*source.native);
        coverage.push_back(c);
    }
    QJsonObject result{{"events", events}, {"subjects", subjects}, {"hits", hits}, {"coverage", coverage}};
    QJsonArray attempts, authorizations, traffic;
    for (const auto &event : state.nativeAttempts) attempts.push_back(eventJson(event));
    for (const auto &event : state.nativeAuthorizations) authorizations.push_back(eventJson(event));
    for (const auto &event : state.nativeTraffic) traffic.push_back(eventJson(event));
    if (!attempts.isEmpty() || !authorizations.isEmpty() ||
        std::any_of(state.coverage.begin(), state.coverage.end(), [](const Coverage &c) { return bool(c.native); })) {
        result["nativeAttempts"] = attempts; result["nativeAuthorizations"] = authorizations;
        if (!traffic.isEmpty()) result["nativeTraffic"] = traffic;
    }
    return result;
}
bool historyRead(const QJsonValue &value, HistoryState &state, bool nativeAllowed = false) {
    if (!value.isObject()) return false;
    const auto object = value.toObject();
    if (!object["events"].isArray() || object["events"].toArray().size() > 4096 ||
        !object["coverage"].isArray() || object["coverage"].toArray().size() > 128 ||
        !object["subjects"].isObject() || object["subjects"].toObject().size() > 20000 ||
        !object["hits"].isObject() || object["hits"].toObject().size() > 20000) return false;
    QSet<QString> sourceKeys;
    for (const auto &entry : object["coverage"].toArray()) {
        if (!entry.isObject()) return false;
        const auto row = entry.toObject();
        Coverage source;
        source.sourceId = row["source"].toString(); source.sourceEpoch = row["epoch"].toString();
        source.declaredScope = row["scope"].toString(); source.sinceUtc = dateRead(row["since"]);
        const auto key = QString::number(source.sourceId.size()) + ':' + source.sourceId + source.sourceEpoch;
        if (!stringFields(row, {"source", "epoch", "scope", "since", "lastSequence"}) ||
            source.sourceId.isEmpty() || source.sourceEpoch.isEmpty() || sourceKeys.contains(key) ||
            !source.sinceUtc.isValid() || !decimalUnsigned(row["lastSequence"].toString(), &source.lastSequence) ||
            !row["synthetic"].isBool() || !row["status"].isDouble() ||
            row["status"].toDouble() != row["status"].toInt() || row["status"].toInt() < 0 ||
            row["status"].toInt() > 2 || !row["gaps"].isArray() || row["gaps"].toArray().size() > 128) return false;
        sourceKeys.insert(key); source.synthetic = row["synthetic"].toBool();
        source.status = CoverageStatus(row["status"].toInt());
        if (row.contains("native")) {
            NativeSourceBinding binding;
            if (!nativeAllowed || source.synthetic || !bindingRead(row["native"], binding) ||
                source.sourceId != nativeSourceId(binding) || source.sourceEpoch != nativeEpochKey(binding)) return false;
            source.native = binding;
        }
        if (!source.synthetic && !source.native && source.status != CoverageStatus::Unavailable) return false;
        if (!row["checkpoint"].isNull()) {
            source.checkpointUtc = dateRead(row["checkpoint"]);
            if (!source.checkpointUtc.isValid()) return false;
        }
        if (!row["lastObserved"].isNull()) {
            source.lastObservedUtc = dateRead(row["lastObserved"]);
            if (!source.lastObservedUtc.isValid()) return false;
        }
        for (const auto &item : row["gaps"].toArray()) {
            const auto parsed = item.toObject(); CoverageGap gap;
            gap.atUtc = dateRead(parsed["at"]); gap.reason = parsed["reason"].toString();
            if (!gap.atUtc.isValid() || gap.reason.isEmpty() || !decimalUnsigned(parsed["lost"].toString(), &gap.lost)) return false;
            if (source.native) {
                if (!parsed["lostKnown"].isBool() || !parsed["remote"].isBool() ||
                    !decimalUnsigned(parsed["after"].toString(), &gap.after) ||
                    !decimalUnsigned(parsed["resync"].toString(), &gap.resync) ||
                    !decimalUnsigned(parsed["revision"].toString(), &gap.revision) ||
                    !parsed["nativeReason"].isDouble() || parsed["nativeReason"].toDouble() != parsed["nativeReason"].toInt() ||
                    parsed["nativeReason"].toInt() < 0 || parsed["nativeReason"].toInt() > 4) return false;
                gap.lostKnown = parsed["lostKnown"].toBool(); gap.remote = parsed["remote"].toBool();
                gap.nativeReason = quint8(parsed["nativeReason"].toInt());
                if ((!gap.lostKnown && gap.lost) || gap.resync > source.lastSequence ||
                    (gap.remote && (!gap.nativeReason || gap.after > gap.resync || (gap.lostKnown &&
                      (!gap.lost || gap.after >= gap.resync || gap.lost != gap.resync - gap.after)))) ||
                    (!gap.remote && (gap.nativeReason || gap.after || gap.revision))) return false;
            }
            source.gaps.push_back(gap);
        }
        state.coverage.push_back(source);
    }
    const auto knownSource = [&](const QString &id, const QString &epoch, bool native = false) {
        for (const auto &source : state.coverage)
            if (source.sourceId == id && source.sourceEpoch == epoch &&
                (native ? bool(source.native) : source.synthetic)) return true;
        return false;
    };
    const auto readEvent = [&](const QJsonValue &entry, ActivityEvent &event) {
        if (!entry.isObject()) return false;
        const auto row = entry.toObject();
        event.sourceId = row["source"].toString(); event.sourceEpoch = row["epoch"].toString();
        event.sequence = row["sequence"].toString(); event.observedAtUtc = dateRead(row["observed"]);
        event.receivedAtUtc = dateRead(row["received"]); event.subjectId = row["subject"].toString();
        event.requestId = row["request"].toString(); event.flowId = row["flow"].toString();
        event.winningRuleId = row["rule"].toString(); event.winningRuleRevision = row["ruleRevision"].toString();
        event.endpoint = row["endpoint"].toString(); event.protocol = row["protocol"].toString();
        if (row.contains("native")) {
            NativeEvidence evidence;
            if (!nativeAllowed || !evidenceRead(row["native"], evidence)) return false;
            event.native = evidence;
        }
        if (!stringFields(row, {"source", "epoch", "sequence", "received", "subject", "request", "flow", "rule", "ruleRevision", "endpoint", "protocol"}) ||
            !knownSource(event.sourceId, event.sourceEpoch, bool(event.native)) || !decimalUnsigned(event.sequence) || event.sequence == "0" ||
            (!event.observedAtUtc.isValid() && !(event.native && row["observed"].isNull())) || !event.receivedAtUtc.isValid() || !row["kind"].isDouble() ||
            row["kind"].toDouble() != row["kind"].toInt() || row["kind"].toInt() < 0 || row["kind"].toInt() > 4 ||
            !row["synthetic"].isBool() || row["synthetic"].toBool() == bool(event.native) ||
            !optionalActionRead(row["action"], event.action)) return false;
        event.synthetic = row["synthetic"].toBool(); event.kind = ActivityKind(row["kind"].toInt());
        for (const auto &source : state.coverage)
            if (source.sourceId == event.sourceId && source.sourceEpoch == event.sourceEpoch &&
                source.lastSequence < event.sequence.toULongLong()) return false;
        if (event.kind == ActivityKind::Authorization && (!event.action || *event.action == Action::Ask)) return false;
        if (!event.winningRuleId.isEmpty() && !decimalUnsigned(event.winningRuleRevision)) return false;
        if (event.winningRuleId.isEmpty() && !event.winningRuleRevision.isEmpty()) return false;
        if (!row["instance"].isNull()) {
            const auto instance = row["instance"].toObject(); quint64 pid = 0, creation = 0;
            if (!decimalUnsigned(instance["pid"].toString(), &pid) || pid > std::numeric_limits<quint32>::max() ||
                !decimalUnsigned(instance["creation"].toString(), &creation) || creation == 0 ||
                instance["epoch"].toString() != event.sourceEpoch) return false;
            event.instance = ProcessInstance{event.sourceEpoch, quint32(pid), creation};
        }
        if (!row["bytes"].isNull()) {
            quint64 bytes = 0;
            if (event.kind != ActivityKind::Traffic || !decimalUnsigned(row["bytes"].toString(), &bytes)) return false;
            event.bytes = bytes;
        }
        return !event.native || validNativeEvent(event);
    };
    for (const auto &entry : object["events"].toArray()) {
        ActivityEvent event;
        if (!readEvent(entry, event)) return false;
        state.events.push_back(std::move(event));
    }
    if (nativeAllowed) {
        for (const auto key : {"nativeAttempts", "nativeAuthorizations", "nativeTraffic"}) {
            if (QString::fromLatin1(key) == "nativeTraffic" && !object.contains(key)) continue;
            if (!object[key].isArray() || object[key].toArray().size() > 20000) return false;
            auto &map = QString::fromLatin1(key) == "nativeAttempts" ? state.nativeAttempts :
                QString::fromLatin1(key) == "nativeAuthorizations" ? state.nativeAuthorizations : state.nativeTraffic;
            for (const auto &entry : object[key].toArray()) {
                ActivityEvent event;
                if (!readEvent(entry, event) || !event.native || map.contains(nativeEventKey(event))) return false;
                map.insert(nativeEventKey(event), std::move(event));
            }
        }
    } else if (object.contains("nativeAttempts") || object.contains("nativeAuthorizations") || object.contains("nativeTraffic")) return false;
    const auto subjects = object["subjects"].toObject();
    for (auto it = subjects.begin(); it != subjects.end(); ++it) {
        if (it.key().isEmpty() || !it.value().isObject()) return false;
        const auto row = it.value().toObject(); ActivityAggregate aggregate;
        if (!optionalFactRead(row["attempt"], aggregate.lastAttempt, nativeAllowed) ||
            !optionalFactRead(row["authorized"], aggregate.lastAuthorized, nativeAllowed) ||
            !optionalFactRead(row["traffic"], aggregate.lastTraffic, nativeAllowed)) return false;
        for (const auto *fact : {&aggregate.lastAttempt, &aggregate.lastAuthorized, &aggregate.lastTraffic})
            if (*fact && !(knownSource((*fact)->sourceId, (*fact)->sourceEpoch, true) ||
                ((*fact)->atUtc.isValid() && knownSource((*fact)->sourceId, (*fact)->sourceEpoch)))) return false;
        state.subjects.insert(it.key(), aggregate);
    }
    const auto hits = object["hits"].toObject();
    for (auto it = hits.begin(); it != hits.end(); ++it) {
        EventFact fact;
        if (it.key().isEmpty() || !factRead(it.value(), fact) || !knownSource(fact.sourceId, fact.sourceEpoch)) return false;
        state.ruleHits.insert(it.key(), fact);
    }
    return validNativeHistory(state);
}
bool boundedJson(const QJsonValue &value, int depth, int &count) {
    if (++count > 2000000 || depth > 80) return false;
    if (value.isString()) return value.toString().size() <= 32768;
    if (value.isArray()) {
        for (const auto &entry : value.toArray()) if (!boundedJson(entry, depth + 1, count)) return false;
    } else if (value.isObject()) {
        const auto object = value.toObject();
        for (auto it = object.begin(); it != object.end(); ++it)
            if (it.key().size() > 32768 || !boundedJson(it.value(), depth + 1, count)) return false;
    }
    return true;
}
bool documentRead(const QJsonObject &object, ReviewDocument &document) {
    int count = 0;
    const bool native = object["schemaVersion"] == 3;
    const bool qname = object["schemaVersion"] == 2 || (native && object.contains("qnameEvidence"));
    if (!(boundedJson(object, 0, count) && (object["schemaVersion"] == 1 || qname || native) &&
           decimalUnsigned(object["storeRevision"].toString(), &document.revision) &&
           reportRead(object["report"], document.report) && historyRead(object["history"], document.history, native))) return false;
    if (!qname) return true;
    QNameEvidence evidence;
    if (!qnameEvidenceRead(object["qnameEvidence"], evidence)) return false;
    document.qnameEvidence = std::move(evidence);
    return rebuildQNameReport(document);
}
QJsonObject documentJson(const ReviewDocument &document) {
    const bool native = std::any_of(document.history.coverage.begin(), document.history.coverage.end(),
                                   [](const Coverage &c) { return bool(c.native); });
    QJsonObject object{{"schemaVersion", native ? 3 : document.qnameEvidence ? 2 : 1}, {"storeRevision", QString::number(document.revision)},
            {"report", reportJson(document.report)}, {"history", historyJson(document.history)}};
    if (document.qnameEvidence) object["qnameEvidence"] = qnameEvidenceJson(*document.qnameEvidence);
    return object;
}
bool safeNode(const XmlNode &node, int depth, int &count) {
    if (depth > 32 || ++count > 200000 || node.attributes.size() > 32 ||
        node.name.size() > 32768 || node.nameSpace.size() > 32768 || node.text.size() > 32768) return false;
    for (auto it = node.attributes.begin(); it != node.attributes.end(); ++it)
        if (it.key().size() > 32768 || it.value().size() > 32768) return false;
    for (const auto &child : node.children) if (!safeNode(child, depth + 1, count)) return false;
    return true;
}
bool safeDocument(const ReviewDocument &document) {
    if (document.report.candidates.size() > 10000 ||
        document.report.filters.size() + document.report.identities.size() > 20000 ||
        document.history.events.size() > 4096 || document.history.coverage.size() > 128 ||
        document.history.subjects.size() > 20000 || document.history.ruleHits.size() > 20000 ||
        !validNativeHistory(document.history)) return false;
    int count = 0;
    for (const auto &candidate : document.report.candidates) if (!safeNode(candidate.source, 1, count)) return false;
    for (const auto &node : document.report.filters) if (!safeNode(node, 1, count)) return false;
    for (const auto &node : document.report.identities) if (!safeNode(node, 1, count)) return false;
    return true;
}
} // namespace
ReviewStore::ReviewStore(const QString &ownRoot) {
    if (ownRoot.isEmpty() || !QDir::isAbsolutePath(ownRoot)) rootError_ = "An absolute application directory is required";
    else path_ = QDir(QDir::cleanPath(ownRoot)).filePath("review.json");
}
ReviewStore::~ReviewStore() = default;
bool ReviewStore::ensureOwner() {
    if (!rootError_.isEmpty()) return false;
    if (owner_) return owner_->isLocked() || owner_->tryLock(0);
    if (!QDir().mkpath(QFileInfo(path_).absolutePath())) return false;
    owner_ = std::make_unique<QLockFile>(path_ + ".lock");
    owner_->setStaleLockTime(0);
    return owner_->tryLock(0);
}
StoreResult ReviewStore::load() {
    if (!rootError_.isEmpty()) return failure(StoreStatus::Invalid, "Invalid application directory");
    if (!ensureOwner()) return failure(StoreStatus::Busy, "Review is in use or the directory is unavailable");
    QFile file(path_);
    if (!file.open(QIODevice::ReadOnly))
        return failure(file.error() == QFileDevice::OpenError && !QFileInfo::exists(path_)
                           ? StoreStatus::Missing : StoreStatus::IoError, "Review is unavailable");
    const auto bytes = file.read(storeByteLimit + 1);
    if (file.error() != QFileDevice::NoError) return failure(StoreStatus::IoError, "Read did not complete");
    if (bytes.size() > storeByteLimit) return failure(StoreStatus::Corrupt, "Review exceeds the size limit");
    const auto preflight = scanReviewJson(bytes);
    if (!preflight.syntax || ((preflight.schema == 2 || preflight.schema == 3) && !preflight.schema2Budget))
        return failure(StoreStatus::Corrupt, "Review failed preflight; the file has been preserved");
    QJsonParseError error;
    const auto parsed = QJsonDocument::fromJson(bytes, &error);
    if (error.error != QJsonParseError::NoError || !parsed.isObject())
        return failure(StoreStatus::Corrupt, "Review is corrupt; the file has been preserved");
    const auto object = parsed.object();
    if (object["schemaVersion"].isDouble() && object["schemaVersion"].toDouble() > 3)
        return failure(StoreStatus::FutureSchema, "Review uses a newer format; the file has been preserved");
    ReviewDocument document;
    if (!documentRead(object, document)) return failure(StoreStatus::Corrupt, "Review is invalid; the file has been preserved");
    return {StoreStatus::Ok, {}, document};
}
StoreResult ReviewStore::save(const ReviewDocument &document, quint64 expectedRevision) {
    if (!safeDocument(document)) return failure(StoreStatus::Invalid, "Data exceeds the limits");
    if (document.qnameEvidence && !budgetQNameReview(document))
        return failure(StoreStatus::Invalid, "Review exceeds the preflight limits");
    const auto previous = load();
    if (!previous.ok() && previous.status != StoreStatus::Missing) return previous;
    if (previous.document && previous.document->qnameEvidence && !document.qnameEvidence)
        return failure(StoreStatus::Invalid, "Review evidence cannot be discarded");
    if ((previous.document ? previous.document->revision : 0) != expectedRevision ||
        document.revision != expectedRevision) return failure(StoreStatus::StaleRevision, "Review has changed; reload it before saving");
    if (expectedRevision == std::numeric_limits<quint64>::max())
        return failure(StoreStatus::Invalid, "Revision is out of range");
    auto next = document;
    next.revision = expectedRevision + 1;
    qint64 jsonBound = storeByteLimit;
    if (next.qnameEvidence && (!rebuildQNameReport(next) || !budgetQNameReview(next, &jsonBound)))
        return failure(StoreStatus::Invalid, "Invalid QName review data");
    const auto object = documentJson(next);
    ReviewDocument validated;
    if (!documentRead(object, validated)) return failure(StoreStatus::Invalid, "Invalid review data");
    const auto bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);
    if (object["schemaVersion"] == 3) {
        const auto preflight = scanReviewJson(bytes);
        if (!preflight.syntax || !preflight.schema2Budget)
            return failure(StoreStatus::Invalid, "History exceeds the preflight limits");
    }
    if (bytes.size() > storeByteLimit || bytes.size() > jsonBound) return failure(StoreStatus::Invalid, "Review exceeds the size limit");
    QSaveFile file(path_);
    file.setDirectWriteFallback(false);
    if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit())
        return failure(StoreStatus::IoError, "Could not save; the previous review has been preserved");
    return {StoreStatus::Ok, {}, validated};
}
} // namespace Gate::Data
