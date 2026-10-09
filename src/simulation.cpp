#include "simulation.h"
#include <QLocale>
#include <QTimeZone>
#include <QTimer>
#include <algorithm>

namespace Gate {
QString policyText(Policy p) {
    return p == Policy::Allow ? "Allow" : p == Policy::Block ? "Block" : "Ask";
}
QString eventText(EventKind k) {
    switch (k) {
    case EventKind::Attempt:
        return "Blocked attempt";
    case EventKind::Authorization:
        return "Authorized attempt";
    case EventKind::Traffic:
        return "Observed traffic";
    case EventKind::Decision:
        return "Decision saved";
    }
    return {};
}
QDateTime sampleNow() {
    return QDateTime(QDate(2026, 10, 8), QTime(10, 42, 40),
                     QTimeZone::fromSecondsAheadOfUtc(-10800));
}
QString relativeTime(qint64 s) {
    if (s < 0)
        return "Not observed";
    if (s < 60)
        return QString::number(s) + " s ago";
    if (s < 3600)
        return QString::number(s / 60) + " min ago";
    if (s < 86400)
        return QString::number(s / 3600) + " h ago";
    return QString::number(s / 86400) + (s < 172800 ? " day ago" : " days ago");
}
QString absoluteTime(qint64 s) {
    if (s < 0)
        return "No sample event";
    return QLocale(QLocale::English).toString(sampleNow().addSecs(-s), "yyyy-MM-dd HH:mm:ss") +
           " UTC−03";
}
QString timestamp(qint64 s) { return relativeTime(s) + "\n" + absoluteTime(s); }

Simulation::Simulation(QObject *parent) : QObject(parent) {
    const QStringList names{"sample-browser.exe", "sample-chat.exe",     "sample-player.exe",
                            "sample-editor.exe",  "sample-uploader.exe", "sample-tool.exe",
                            "sample-license.exe", "svchost.exe",         "sample-agent.exe",
                            "sample-browser.exe", "All applications",    "sample-render.exe"};
    const QStringList notes{"Executable path matches",
                            "Executable path matches",
                            "Executable path matches",
                            "Executable path matches",
                            "Executable path matches",
                            "Executable path matches",
                            "Executable path matches",
                            "Service identity missing; no mapping",
                            "Wildcard path needs explicit scope",
                            "Conflicting destination exception",
                            "Filter-based permission not translated",
                            "Bandwidth limit has no firewall equivalent"};
    for (int i = 0; i < names.size(); ++i)
        import_.push_back(
            {"import-" + QString::number(i), names[i],
             (i == 1 || i == 2 || i == 4 || i == 6 || i == 9) ? Policy::Block : Policy::Allow,
             i < 7    ? "Ready"
             : i < 10 ? "Needs review"
                      : "Unsupported",
             notes[i], i == 11});
    reset();
}
void Simulation::reset() {
    ++epoch_;
    service_ = Service::Available;
    backup_.reset();
    data_ = {};
    data_.processes = {
        {"firefox", "firefox.exe", "Mozilla Corporation",
         "C:\\Program Files\\Mozilla Firefox\\firefox.exe", Policy::Allow, true, 12, 12, 11,
         "This executable", "Permanent", 8, false, "Verified publisher", "203.0.113.24:443",
         "TCP · IPv4", "FF"},
        {"nuke", "Nuke16.0.exe", "Foundry", "C:\\Program Files\\Nuke16.0v5\\Nuke16.0.exe",
         Policy::Block, true, 54, -1, -1, "This executable", "Permanent", 28, false,
         "Verified publisher", "198.51.100.18:443", "TCP · IPv4", "N"},
        {"updater", "sample-updater.exe", "Example Software Ltd.",
         "C:\\Program Files\\Example App\\sample-updater.exe", Policy::Ask, true, 4, -1, -1,
         "Unmatched executable", "—", 0, false, "Verified publisher", "203.0.113.18:443",
         "TCP · IPv4", "U"},
        {"onedrive", "OneDrive.exe", "Microsoft Corporation",
         "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", Policy::Allow, true, 90, 90, 88,
         "This executable", "Permanent", 45, false, "Verified publisher", "203.0.113.61:443",
         "TCP · IPv4", "OD"},
        {"telemetry", "sample-telemetry.exe", "Publisher not verified",
         "C:\\Demo Apps\\Utilities\\sample-telemetry.exe", Policy::Ask, true, 25, -1, -1,
         "Unmatched executable", "—", 0, false, "Not verified", "198.51.100.31:443", "UDP · IPv4",
         "T"},
        {"svchost", "svchost.exe", "Microsoft Corporation", "C:\\Windows\\System32\\svchost.exe",
         Policy::Block, true, 145, -1, -1, "Service: DemoTelemetry", "Permanent", 65, false,
         "Verified publisher", "198.51.100.47:443", "TCP · IPv4", "W", true},
        {"render", "render-helper.exe", "Example Studio",
         "C:\\Demo Apps\\Render\\render-helper.exe", Policy::Block, false, 2040, 86400, 86420,
         "This executable", "Permanent", 14, false, "Not verified", "203.0.113.72:443",
         "TCP · IPv4", "R"},
        {"helper", "sample-helper.exe", "Example Software Ltd.",
         "C:\\Demo Apps\\Helper\\sample-helper.exe", Policy::Ask, true, 46, -1, -1,
         "Unmatched executable", "—", 0, false, "Verified publisher", "[2001:db8::24]:443",
         "TCP · IPv6", "H"},
        {"legacy", "legacy-sync.exe", "Example Archive Tools",
         "C:\\Demo Apps\\Archive\\legacy-sync.exe", Policy::Allow, false, 185 * 86400, 185 * 86400,
         -1, "This executable", "Permanent", 260, true, "Executable missing", "198.51.100.12:443",
         "TCP · IPv4", "LS"},
        {"old-updater", "old-updater.exe", "Example Software Ltd.",
         "C:\\Demo Apps\\Old Version\\old-updater.exe", Policy::Block, false, 214 * 86400, -1, -1,
         "This executable", "Permanent", 280, true, "Executable missing", "203.0.113.8:80",
         "TCP · IPv4", "OU"},
        {"backup", "backup-agent.exe", "Example Backup Co.",
         "C:\\Demo Apps\\Backup\\backup-agent.exe", Policy::Allow, false, 193 * 86400, 193 * 86400,
         193 * 86400, "This executable", "Permanent", 310, false, "Verified publisher",
         "203.0.113.66:443", "TCP · IPv4", "B"},
        {"system", "System", "Windows kernel", "Windows kernel · no executable path", Policy::Block,
         true, 520, -1, -1, "System identity (proposal)", "Permanent", 11, false, "System identity",
         "198.51.100.60:443", "TCP · IPv4", "S", true}};
    for (const auto &p : data_.processes)
        if (p.policy != Policy::Ask)
            data_.rules.push_back(
                {p.id, p.name, p.policy, p.scope, "Demo rule", p.attempt, p.ruleDays, p.missing});
    data_.pending = {"updater", "telemetry", "helper"};
    data_.events = {
        {"sample-updater.exe", EventKind::Attempt, 4, "203.0.113.18:443",
         "Waiting for a decision · 3 attempts"},
        {"firefox.exe", EventKind::Authorization, 12, "203.0.113.24:443",
         "Allowed by executable rule"},
        {"firefox.exe", EventKind::Traffic, 11, "203.0.113.24:443",
         "Traffic observed after authorization"},
        {"sample-telemetry.exe", EventKind::Attempt, 25, "198.51.100.31:443",
         "Unmatched · awaiting a decision"},
        {"Nuke16.0.exe", EventKind::Attempt, 54, "198.51.100.18:443", "Blocked by executable rule"},
        {"OneDrive.exe", EventKind::Authorization, 90, "203.0.113.61:443",
         "Allowed by executable rule"},
        {"OneDrive.exe", EventKind::Traffic, 88, "203.0.113.61:443",
         "Traffic observed after authorization"},
        {"svchost.exe", EventKind::Attempt, 145, "198.51.100.47:443",
         "Blocked for service DemoTelemetry"},
        {"sample-helper.exe", EventKind::Attempt, 46, "[2001:db8::24]:443",
         "Unmatched · awaiting a decision"},
        {"System", EventKind::Attempt, 520, "198.51.100.60:443", "System identity · demo policy"}};
    history_ = Data::ActivityHistory{};
    eventSequence_ = 0;
    history_.addSyntheticSource("simulation", QString::number(epoch_), "Offline sample events");
    for (auto &event : data_.events) {
        event.id = "simulation-event:" + QString::number(epoch_) + ":" + QString::number(++eventSequence_);
        recordHistory(event);
    }
    emit invalidated();
    emit changed();
}
const Process *Simulation::process(const QString &id) const {
    for (const auto &p : data_.processes)
        if (p.id == id)
            return &p;
    return nullptr;
}
const Rule *Simulation::rule(const QString &id) const {
    for (const auto &r : data_.rules)
        if (r.id == id)
            return &r;
    return nullptr;
}
bool Simulation::setReview(const QString &id, quint64 e, const Review &review) {
    if (!writable(e) || !isPending(id) || review.scope < 0 || review.scope > 1 ||
        review.duration < 0 || review.duration > 2)
        return false;
    data_.reviews[id] = review;
    return true;
}
void Simulation::recordDecision(const QString &name, const QString &reason) {
    Event event{name, EventKind::Decision, 0, "—", reason,
                "simulation-event:" + QString::number(epoch_) + ":" + QString::number(++eventSequence_)};
    data_.events.prepend(event);
    if (data_.events.size() > 4096) {
        data_.events.removeLast();
        history_.gap("simulation", history_.state().coverage.front().sourceEpoch, "DetailRetention", 1);
    }
    recordHistory(event);
}
void Simulation::recordHistory(const Event &event) {
    Data::ActivityEvent fact;
    fact.sourceId = "simulation"; fact.sourceEpoch = history_.state().coverage.front().sourceEpoch;
    fact.sequence = QString::number(eventSequence_); fact.subjectId = event.name;
    fact.synthetic = true; fact.observedAtUtc = sampleNow().addSecs(-event.age).toUTC();
    fact.receivedAtUtc = sampleNow().toUTC(); fact.endpoint = event.destination;
    fact.kind = event.kind == EventKind::Attempt ? Data::ActivityKind::Attempt
              : event.kind == EventKind::Authorization ? Data::ActivityKind::Authorization
              : event.kind == EventKind::Traffic ? Data::ActivityKind::Traffic : Data::ActivityKind::HumanDecision;
    if (event.kind == EventKind::Authorization) fact.action = Data::Action::Allow;
    history_.ingest(fact);
    if (history_.flushDue(fact.receivedAtUtc)) history_.checkpoint(fact.receivedAtUtc);
    data_.history = history_.state();
}
void Simulation::setEnabled(bool enabled) {
    if (enabled_ == enabled) return;
    enabled_ = enabled; ++epoch_; emit invalidated(); emit changed();
}
bool Simulation::decide(const QString &id, quint64 e, Policy policy) {
    if (!writable(e) || !isPending(id) || !process(id) || policy == Policy::Ask)
        return false;
    const auto options = review(id);
    const QString scope = options.scope ? "Current process (simulation)" : "This executable";
    const QString duration = options.duration == 1   ? "15 minutes (simulation)"
                             : options.duration == 2 ? "Until restart (simulation)"
                                                     : "Permanent in this session";
    for (auto &p : data_.processes)
        if (p.id == id) {
            p.policy = policy;
            p.scope = scope;
            p.duration = duration;
            data_.rules.erase(std::remove_if(data_.rules.begin(), data_.rules.end(),
                                             [&](const Rule &r) { return r.id == id; }),
                              data_.rules.end());
            data_.rules.push_back({id, p.name, policy, scope, "Demo decision", p.attempt, 0,
                                   p.missing, true, duration});
            recordDecision(p.name,
                           policyText(policy) + " rule saved; new attempt required · simulation");
            break;
        }
    data_.pending.remove(id);
    data_.reviews.remove(id);
    emit requestResolved(id);
    emit changed();
    return true;
}
bool Simulation::editRule(const QString &id, quint64 e, Policy policy) {
    if (!writable(e) || (!process(id) && !rule(id)) || (rule(id) && !rule(id)->active))
        return false;
    const QString name = process(id) ? process(id)->name : rule(id)->name;
    for (auto &p : data_.processes)
        if (p.id == id) {
            p.policy = policy;
            if (policy == Policy::Ask)
                p.scope = "Unmatched executable";
            else if (p.scope == "Unmatched executable")
                p.scope = p.id == "svchost"  ? "Service: DemoTelemetry"
                          : p.id == "system" ? "System identity (proposal)"
                                             : "This executable";
            p.duration = policy == Policy::Ask ? "—" : "Permanent in this session";
        }
    if (policy == Policy::Ask) {
        data_.rules.erase(std::remove_if(data_.rules.begin(), data_.rules.end(),
                                         [&](const Rule &r) { return r.id == id; }),
                          data_.rules.end());
    } else if (rule(id)) {
        for (auto &r : data_.rules)
            if (r.id == id) {
                r.policy = policy;
                r.duration = "Permanent in this session";
                if (const auto *p = process(id))
                    r.scope = p->scope;
            }
    } else if (const auto *p = process(id))
        data_.rules.push_back({id, name, policy, p->scope, "Demo edit", p->attempt, 0, p->missing,
                               true, p->duration});
    if (policy != Policy::Ask && isPending(id)) {
        data_.pending.remove(id);
        data_.reviews.remove(id);
        emit requestResolved(id);
    }
    // Cambiar a Ask no inventa una nueva solicitud ni evidencia de trafico.
    recordDecision(name, policyText(policy) + " policy saved · simulation");
    emit changed();
    return true;
}
bool Simulation::activate(const QString &id, quint64 e, Policy policy) {
    if (!writable(e) || policy == Policy::Ask || !rule(id) || rule(id)->active)
        return false;
    for (auto &r : data_.rules)
        if (r.id == id) {
            r.active = true;
            r.policy = policy;
            recordDecision(r.name, "Reviewed sample candidate activated: " + policyText(policy));
            break;
        }
    emit changed();
    return true;
}
bool Simulation::loadImport(quint64 e) {
    if (!writable(e) || data_.importLoaded)
        return false;
    data_.importLoaded = true;
    emit changed();
    return true;
}
bool Simulation::resetImport(quint64 e) {
    if (!writable(e) || !data_.importLoaded)
        return false;
    data_.importLoaded = false;
    emit changed();
    return true;
}
bool Simulation::applyImport(quint64 e) {
    if (!writable(e) || !data_.importLoaded || data_.importApplied)
        return false;
    for (const auto &r : import_)
        if (r.status == "Ready" && !rule(r.id))
            data_.rules.push_back(
                {r.id, r.name, r.policy, "This executable", "Sample import", -1, 0, false, false});
    data_.importApplied = true;
    emit changed();
    return true;
}
QVector<Rule> Simulation::cleanupCandidates(int days) const {
    QVector<Rule> list;
    if (days != 90 && days != 180 && days != 365)
        return list;
    for (const auto &r : data_.rules)
        if (r.active && r.last >= qint64(days) * 86400 && r.id != "system" && r.id != "svchost")
            list.push_back(r);
    return list;
}
bool Simulation::cleanup(const QSet<QString> &ids, int days, quint64 e) {
    if (!writable(e) || ids.isEmpty())
        return false;
    QSet<QString> valid;
    for (const auto &r : cleanupCandidates(days))
        valid.insert(r.id);
    for (const auto &id : ids)
        if (!valid.contains(id))
            return false;
    backup_ = data_;
    data_.rules.erase(std::remove_if(data_.rules.begin(), data_.rules.end(),
                                     [&](const Rule &r) { return ids.contains(r.id); }),
                      data_.rules.end());
    for (auto &p : data_.processes)
        if (ids.contains(p.id)) {
            p.policy = Policy::Ask;
            p.scope = "Unmatched executable";
            p.duration = "—";
        }
    ++epoch_;
    emit invalidated();
    emit changed();
    return true;
}
bool Simulation::restore(quint64 e) {
    if (!writable(e) || !backup_)
        return false;
    data_ = *backup_;
    history_.restore(data_.history);
    data_.history = history_.state();
    backup_.reset();
    ++epoch_;
    emit invalidated();
    emit changed();
    return true;
}
void Simulation::setService(Service s) {
    if (s == service_)
        return;
    service_ = s;
    ++epoch_;
    emit invalidated();
    emit changed();
}

Explanation::Explanation(Simulation *model)
    : QObject(model), model_(model), transport_(this), coordinator_(transport_, this) {
    connect(&coordinator_, &Assistance::ExplanationCoordinator::changed, this, &Explanation::changed);
    connect(model_, &Simulation::invalidated, this, &Explanation::close);
    connect(model_, &Simulation::requestResolved, this, [this](const QString &id) {
        if (visible_ == id) close();
    });
    setFixture(ExplanationState::Known);
}
Assistance::RequestContext Explanation::context() const {
    return {"simulation:" + visible_, "sample-public-catalog", model_->epoch(), model_->epoch(),
            demoGeneration_, model_->isPending(visible_), model_->available()};
}
ExplanationState Explanation::status() const {
    using S = Assistance::Status;
    switch (coordinator_.status()) {
    case S::Loading: return ExplanationState::Loading;
    case S::Known: return ExplanationState::Known;
    case S::Unclear: return ExplanationState::Unclear;
    case S::Idle: case S::Cancelled: return ExplanationState::Idle;
    default: return ExplanationState::Error;
    }
}
QString Explanation::text() const {
    const auto result = coordinator_.explanation();
    return result ? "Possible purpose\n" + result->possiblePurpose + "\n\nPossible network reason\n" +
                    result->possibleNetworkReason + "\n\n" + result->caution : QString{};
}
QString Explanation::problem() const {
    return coordinator_.status() == Assistance::Status::Uncertain
        ? "The sample outcome is uncertain. This sample request will not be retried. The access request remains pending."
        : coordinator_.status() == Assistance::Status::Limited
        ? "Sample explanation limit reached. The access request remains pending."
        : "The sample explanation could not be loaded. The access request remains pending.";
}
void Explanation::configure(bool on) { coordinator_.configureDemo(on, on && consent()); }
void Explanation::setConsent(bool on) { coordinator_.configureDemo(configured(), on); }
void Explanation::setAutomatic(bool on) { coordinator_.setAutomatic(on); }
void Explanation::setFixture(ExplanationState fixture) {
    fixture_ = fixture;
    coordinator_.cancel();
    ++demoGeneration_;
    Assistance::MockExplanationTransport::Fixture response;
    response.delayMs = 1100;
    response.body = Assistance::MockExplanationTransport::sampleEnvelope(fixture == ExplanationState::Unclear);
    if (fixture == ExplanationState::Error) response.error = Assistance::Error::Unavailable;
    transport_.setFixture(std::move(response));
    coordinator_.updateContext(context());
}
bool Explanation::open(const QString &id) {
    if (!model_->available() || !model_->isPending(id)) return false;
    visible_ = id;
    coordinator_.open(context(), Assistance::CatalogEntry::SampleEditor);
    return true;
}
void Explanation::close() { visible_.clear(); coordinator_.close(); }
void Explanation::cancel() { coordinator_.cancel(); }
bool Explanation::start() { coordinator_.updateContext(context()); return coordinator_.start(); }
bool Explanation::complete(const QString &, quint64, quint64, ExplanationState) {
    // Las respuestas solo ingresan por el transporte local y el coordinador vinculante.
    return false;
}
} // namespace Gate
