#include "FirewallClient.h"
#include <QFileInfo>
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

const FirewallClient::RuleItem *FirewallClient::ruleFor(const QString &path) const {
    for (const auto &r : rules_)
        if (key(r.path) == key(path)) return &r;
    return nullptr;
}

void FirewallClient::decide(const QString &path, bool allow) {
    enqueue(QString("DECIDE\t%1\t%2").arg(allow ? "allow" : "block", path), Request::Command,
            QString("%1 saved for %2. Its next connection attempt uses this rule.")
                .arg(allow ? "Allow" : "Block", fileName(path)));
    poll();
}

void FirewallClient::removeRule(const QString &path) {
    enqueue("REMOVE\t" + path, Request::Command,
            QString("Rule removed for %1. Its next connection will be blocked and ask again.").arg(fileName(path)));
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
        socket_->connectToServer(ServerName);
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
            if (f.size() != 7) continue;
            pending_.push_back({f[6], f[3], f[0].toLongLong(), f[1].toLongLong(), f[2].toInt(), f[4].toInt(), f[5].toInt()});
            now.insert(key(f[6]));
            if (!firstPending_ && !knownPending_.contains(key(f[6]))) emit newPending(f[6]);
        }
        knownPending_ = now;
        firstPending_ = false;
        break;
    }
    case Request::Rules:
        rules_.clear();
        for (const auto &row : rows) {
            const auto f = row.split('\t');
            if (f.size() != 4) continue;
            rules_.push_back({f[3], f[0] == "allow", f[1].toLongLong(), f[2].toLongLong()});
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
