#include "FirewallClient.h"
#include <QDateTime>
#include <QFileInfo>
#include <QHostAddress>
#include <QLocalSocket>

namespace Gate {
namespace {
constexpr char ServerName[] = "LGA.GateBouncer.Engine";
QString key(const QString &path) { return path.toLower(); }
} // namespace

FirewallClient::FirewallClient(QObject *parent) : QObject(parent), socket_(new QLocalSocket(this)) {
    timer_.setInterval(1000);
    connect(&timer_, &QTimer::timeout, this, &FirewallClient::poll);
    connect(socket_, &QLocalSocket::readyRead, this, &FirewallClient::onReadyRead);
    connect(socket_, &QLocalSocket::connected, this, &FirewallClient::sendNext);
    connect(socket_, &QLocalSocket::disconnected, this, &FirewallClient::onDisconnected);
    connect(socket_, &QLocalSocket::errorOccurred, this, [this](QLocalSocket::LocalSocketError) {
        if (socket_->state() != QLocalSocket::ConnectedState) onDisconnected();
    });
}

QString FirewallClient::fileName(const QString &path) { return QFileInfo(path).fileName(); }

QString FirewallClient::protocolName(int protocol) {
    return protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : protocol == 1 ? "ICMP" : protocol == 58 ? "ICMPv6"
         : protocol ? "IP " + QString::number(protocol) : QString("Unknown");
}

QString FirewallClient::destinationKind(const QString &address) {
    QHostAddress a(address);
    if (a.isNull()) return {};
    bool mapped = false;
    const QHostAddress v4(a.toIPv4Address(&mapped));
    if (mapped) a = v4;
    if (a.isLoopback()) return "This PC";
    // Igual que el permiso de red local del motor: 100.64.0.0/10 y fd7a:115c:a1e0::/48 son las de Tailscale.
    if (a.isInSubnet(QHostAddress("100.64.0.0"), 10) || a.isInSubnet(QHostAddress("fd7a:115c:a1e0::"), 48))
        return "Tailscale";
    if (a.isPrivateUse() || a.isLinkLocal() || a.isMulticast() || a.isBroadcast() || a.isUniqueLocalUnicast())
        return "Local network";
    return "Internet";
}

void FirewallClient::setActive(bool active) {
    if (active == active_) return;
    active_ = active;
    if (active) {
        poll();
        timer_.start();
    } else {
        timer_.stop();
    }
}

void FirewallClient::refreshNow() { poll(); }

const FirewallClient::PendingItem *FirewallClient::pendingFor(const QString &path) const {
    for (const auto &p : pending_)
        if (key(p.path) == key(path)) return &p;
    return nullptr;
}

const FirewallClient::PendingItem *FirewallClient::pendingById(const QString &id) const {
    for (const auto &p : pending_)
        if (key(p.id) == key(id)) return &p;
    return nullptr;
}

const FirewallClient::RuleItem *FirewallClient::ruleFor(const QString &path) const {
    if (path.isEmpty()) return nullptr;
    for (const auto &r : rules_)
        if (r.destination.isEmpty() && key(r.path) == key(path)) return &r;
    return nullptr;
}

int FirewallClient::ruleCount() const {
    int n = 0;
    for (const auto &r : rules_) n += r.scope != "covered";
    return n;
}

const FirewallClient::RuleItem *FirewallClient::ruleById(const QString &id) const {
    for (const auto &r : rules_)
        if (r.scope != "covered" && key(r.id) == key(id)) return &r;
    return nullptr;
}

QString FirewallClient::describe(const RuleItem &rule) {
    const QString who = rule.scope == "app"         ? QString("any version of %1 from %2").arg(rule.name, rule.signer)
                        : rule.scope == "publisher" ? "all apps from " + rule.signer
                                                    : fileName(rule.path);
    return rule.destination.isEmpty() ? who : who + " to " + rule.destination;
}

bool FirewallClient::publisherRuleAllowed(const QString &signer) {
    return !signer.isEmpty() && !signer.startsWith("Microsoft", Qt::CaseInsensitive);
}

QString FirewallClient::describeDuration(qint64 seconds) {
    const qint64 minutes = (seconds + 30) / 60;
    if (minutes >= 60 && minutes % 60 == 0)
        return minutes == 60 ? QStringLiteral("1 hour") : QString("%1 hours").arg(minutes / 60);
    return minutes == 1 ? QStringLiteral("1 minute") : QString("%1 minutes").arg(minutes);
}

QString FirewallClient::remaining(const RuleItem &rule) {
    if (rule.expires == 0) return {};
    if (rule.expires < 0) return QStringLiteral("until restart");
    const qint64 left = rule.expires - QDateTime::currentSecsSinceEpoch();
    if (left <= 60) return QStringLiteral("expires now");
    const qint64 minutes = (left + 59) / 60;
    return minutes < 60 ? QString("%1 min left").arg(minutes)
                        : QString("%1 h %2 min left").arg(minutes / 60).arg(minutes % 60);
}

void FirewallClient::decide(const QString &path, bool allow, const QString &scope, const QString &duration,
                            const QString &destination) {
    const auto *p = pendingFor(path);
    const QString signer = p ? p->signer : QString();
    QString what = fileName(path);
    if (scope == "app") what = QString("any version of %1 from %2").arg(fileName(path), signer);
    else if (scope == "publisher") what = "all apps from " + signer;
    if (!destination.isEmpty()) what += " to " + destination;
    QString line = QString("DECIDE\t%1\t%2\t%3").arg(allow ? "allow" : "block", scope, path);
    if (duration != "always" || !destination.isEmpty()) line += "\t" + duration;
    if (!destination.isEmpty()) line += "\t" + destination;
    const QString span = duration == "restart" ? QStringLiteral(" until restart")
                         : duration == "always" ? QString()
                                                : " for " + describeDuration(duration.toLongLong());
    enqueue(line, Request::Command,
            QString("%1%2 saved for %3. The next connection attempt uses this rule.")
                .arg(allow ? "Allow" : "Block", span, what));
    poll();
}

void FirewallClient::removeRule(const QString &id) {
    const auto *r = ruleById(id);
    const QString what = r ? describe(*r) : fileName(id);
    enqueue("REMOVE\t" + id, Request::Command,
            QString("Rule removed for %1. The next connection will be blocked and ask again.").arg(what));
    poll();
}

void FirewallClient::setLocalNetwork(bool allow) {
    enqueue(QString("LAN\t%1").arg(allow ? "allow" : "ask"), Request::Command,
            allow ? QString("Local network connections no longer ask.")
                  : QString("Local network connections ask like any other."));
    poll();
}

void FirewallClient::setAsk(bool ask) {
    enqueue(QString("MODE\t%1").arg(ask ? "ask" : "off"), Request::Command,
            ask ? QString("Unknown applications are blocked until you decide.")
                : QString("Unknown applications can connect. Saved rules still apply."));
    poll();
}

void FirewallClient::enqueue(const QString &line, Request::Kind kind, const QString &okMessage) {
    if (kind == Request::Command) ++commandsInFlight_;
    queue_.push_back({line, kind, okMessage});
    sendNext();
}

void FirewallClient::poll() {
    if (!active_) return;
    // Un ciclo de lectura a la vez: si el anterior sigue en cola no se apila otro.
    for (const auto &r : queue_)
        if (r.kind == Request::Status) return;
    enqueue("STATUS", Request::Status);
    enqueue("PENDING", Request::Pending);
    enqueue("RULES", Request::Rules);
    enqueue("ACTIVITY", Request::Activity);
}

void FirewallClient::sendNext() {
    if (waiting_ || queue_.empty()) return;
    if (socket_->state() == QLocalSocket::UnconnectedState) {
        // QA: un motor falso en otro canal (GATEBOUNCER_QA_PIPE), para recorrer pedidos sin tocar el firewall. Sólo
        // dentro de un recorrido de QA (GATEBOUNCER_QA_SHOT), como el catálogo de prueba.
        static const QString name = qEnvironmentVariableIsEmpty("GATEBOUNCER_QA_SHOT") ||
                                            qEnvironmentVariableIsEmpty("GATEBOUNCER_QA_PIPE")
                                        ? QString(ServerName)
                                        : qEnvironmentVariable("GATEBOUNCER_QA_PIPE");
        socket_->connectToServer(name);
        return;
    }
    if (socket_->state() != QLocalSocket::ConnectedState) return;
    waiting_ = true;
    buffer_.clear();
    socket_->write(queue_.front().line.toUtf8() + '\n');
}

void FirewallClient::onReadyRead() {
    buffer_ += socket_->readAll();
    // "END" en su propia línea: una ruta que termina en END no corta la respuesta.
    if (!buffer_.endsWith("\nEND\n") || queue_.empty()) return;
    const Request request = queue_.front();
    queue_.pop_front();
    waiting_ = false;
    const QByteArray raw = buffer_;
    buffer_.clear();
    QStringList lines = QString::fromUtf8(raw).split('\n');
    while (!lines.isEmpty() && (lines.last().isEmpty() || lines.last() == "END")) lines.removeLast();
    const int slot = int(request.kind);
    if (request.kind == Request::Command || raw != lastRaw_[slot]) {
        if (request.kind != Request::Command) lastRaw_[slot] = raw;
        apply(request, lines);
    }
    sendNext();
}

void FirewallClient::onDisconnected() {
    waiting_ = false;
    buffer_.clear();
    const bool wasConnected = status_.connected;
    status_ = {};
    for (auto &raw : lastRaw_) raw.clear();
    // Sin motor no hay datos vigentes: se vacía todo para no mostrar reglas o pedidos viejos como actuales.
    pending_.clear();
    rules_.clear();
    activity_.clear();
    while (!queue_.empty()) {
        if (queue_.front().kind == Request::Command) {
            --commandsInFlight_;
            emit commandFinished(false, "GateBouncer engine is not running. Nothing was changed.");
        }
        queue_.pop_front();
    }
    if (wasConnected) emit changed();
}

void FirewallClient::apply(const Request &request, const QStringList &lines) {
    const bool ok = !lines.isEmpty() && lines.first().startsWith("OK");
    if (request.kind == Request::Command) {
        --commandsInFlight_;
        const QString error = !ok && !lines.isEmpty() ? lines.first().section('\t', 1) : QString("No reply");
        emit commandFinished(ok, ok ? request.okMessage : error);
        poll();
        return;
    }
    if (!ok) return;
    const auto rows = lines.mid(1);
    switch (request.kind) {
    case Request::Status: {
        Status s;
        s.connected = true;
        for (const auto &row : rows) {
            const auto name = row.section('\t', 0, 0), value = row.section('\t', 1);
            if (name == "mode") s.ask = value != "off";
            else if (name == "lan") s.localNetwork = value != "ask";
            else if (name == "scope") s.allApps = value == "all";
            else if (name == "dynamic") s.dynamic = value == "1";
            else if (name == "started") s.started = value.toLongLong();
            else if (name == "control") s.control = value == "1";
            else if (name == "lastError") s.lastError = value;
        }
        status_ = s;
        break;
    }
    case Request::Pending: {
        pending_.clear();
        QSet<QString> now;
        for (const auto &row : rows) {
            const auto f = row.split('\t');
            // El motor anterior manda 8 campos; con los nombres de destino, 9; con las reglas por destino, 10 (modo).
            if (f.size() < 8 || f.size() > 10) continue;
            PendingItem p;
            p.path = f[7];
            p.remote = f[3];
            p.first = f[0].toLongLong();
            p.last = f[1].toLongLong();
            p.attempts = f[2].toInt();
            p.port = f[4].toInt();
            p.protocol = f[5].toInt();
            p.signer = f[6];
            p.host = f.size() >= 9 ? f[8] : QString();
            p.perDestination = f.size() == 10 && f[9] == "destination";
            p.id = p.perDestination ? p.path + "|" + p.remote : p.path;
            pending_.push_back(p);
            now.insert(key(p.id));
            // También los que ya esperaban al conectar: la ventana arranca con la sesión y tiene que avisarlos.
            if (!knownPending_.contains(key(p.id))) emit newPending(p.id);
        }
        knownPending_ = now;
        break;
    }
    case Request::Rules:
        rules_.clear();
        for (const auto &row : rows) {
            const auto f = row.split('\t');
            // El motor anterior manda 7 campos; con las reglas temporales, 8 (vencimiento); con las reglas por
            // destino, 10 (destino y ruta).
            if (f.size() != 7 && f.size() != 8 && f.size() != 10) continue;
            RuleItem r;
            r.allow = f[0] == "allow";
            r.created = f[1].toLongLong();
            r.lastBlock = f[2].toLongLong();
            r.scope = f[3];
            r.signer = f[4];
            r.name = f[5];
            r.id = f[6];
            r.expires = f.size() >= 8 ? f[7].toLongLong() : 0;
            r.destination = f.size() == 10 ? f[8] : QString();
            if (r.scope == "path" || r.scope == "covered") r.path = f.size() == 10 ? f[9] : r.id;
            rules_.push_back(r);
        }
        break;
    case Request::Activity:
        activity_.clear();
        for (const auto &row : rows) {
            const auto f = row.split('\t');
            if (f.size() != 6) continue;
            activity_.push_back({f[0].toLongLong(), f[1], f[2], f[5], f[3].toInt(), f[4].toInt()});
        }
        break;
    default:
        break;
    }
    emit changed();
}

} // namespace Gate
