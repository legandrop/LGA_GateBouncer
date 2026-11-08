#include "FirewallClient.h"
#include "folder_rule.h"
#include "i18n.h"
#include <QDateTime>
#include <QDir>
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
         : protocol ? "IP " + QString::number(protocol) : I18n::trc("protocol", "Unknown");
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

QString FirewallClient::destinationKindLabel(const QString &kind) {
    if (kind == QLatin1String("This PC")) return I18n::tr("This PC");
    if (kind == QLatin1String("Local network")) return I18n::tr("Local network");
    return kind; // Internet y Tailscale se dicen igual
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

void FirewallClient::refreshNow() {
    forceFull_ = true;
    poll();
}

void FirewallClient::setRefresh(int rulesMs, int activityMs) {
    rulesMs_ = rulesMs;
    activityMs_ = activityMs;
}

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
    // Por el índice de rutas (la primera regla de la app entera de cada ruta): Apps lo pregunta por cada programa
    // abierto, y recorrer todas las reglas cada vez se notaba.
    const auto found = pathIndex_.constFind(key(path));
    return found == pathIndex_.constEnd() ? nullptr : &rules_[*found];
}

const FirewallClient::RuleItem *FirewallClient::folderRuleFor(const QString &path) const {
    // Como el motor: la carpeta más profunda; en la misma, la que nombra el exe; a igualdad, Block.
    const auto beats = [](const RuleItem &a, const RuleItem &b) {
        if (a.path.size() != b.path.size()) return a.path.size() > b.path.size();
        if (a.name.isEmpty() != b.name.isEmpty()) return !a.name.isEmpty();
        return !a.allow && b.allow;
    };
    const QString p = path.toLower().replace('/', '\\');
    const QString name = fileName(path).toLower();
    const RuleItem *best = nullptr;
    for (const auto &r : rules_) {
        if (r.scope != QLatin1String("folder") || r.path.isEmpty()) continue;
        const QString f = r.path.toLower().replace('/', '\\');
        if (p.size() <= f.size() + 1 || !p.startsWith(f) || p.at(f.size()) != '\\') continue;
        if (!r.name.isEmpty() && r.name.toLower() != name) continue;
        if (!best || beats(r, *best)) best = &r;
    }
    return best;
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
    const QString who = rule.scope == "app"         ? I18n::tr("any version of %1 from %2").arg(rule.name, rule.signer)
                        : rule.scope == "publisher" ? I18n::tr("all apps from %1").arg(rule.signer)
                        : rule.scope == "folder"    ? I18n::tr("%1 in %2").arg(rule.name.isEmpty() ? I18n::tr("all apps")
                                                                                                   : rule.name,
                                                                               rule.path)
                                                    : fileName(rule.path);
    return rule.destination.isEmpty() ? who : I18n::tr("%1 to %2").arg(who, rule.destination);
}

bool FirewallClient::publisherRuleAllowed(const QString &signer) {
    return !signer.isEmpty() && !signer.startsWith("Microsoft", Qt::CaseInsensitive);
}

QString FirewallClient::describeDuration(qint64 seconds) {
    const qint64 minutes = (seconds + 30) / 60;
    if (minutes >= 60 && minutes % 60 == 0)
        return minutes == 60 ? I18n::tr("1 hour") : I18n::tr("%1 hours").arg(minutes / 60);
    return minutes == 1 ? I18n::tr("1 minute") : I18n::tr("%1 minutes").arg(minutes);
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
    // Las opciones de carpeta del aviso traen la carpeta en el alcance: una regla por carpeta es para la app entera.
    if (scope.startsWith("folder:")) {
        trustFolder(scope.mid(7), {}, allow, duration);
        return;
    }
    if (scope.startsWith("foldername:")) {
        // El nombre largo: WFP puede informar el corto 8.3 («GATEBO~1.EXE»), y el motor compara con el de la ruta final.
        const QString full = QString::fromStdWString(gbe::longPathOf(QDir::toNativeSeparators(path).toStdWString()));
        trustFolder(scope.mid(11), fileName(full), allow, duration);
        return;
    }
    const auto *p = pendingFor(path);
    const QString signer = p ? p->signer : QString();
    QString what = fileName(path);
    if (scope == "app") what = I18n::tr("any version of %1 from %2").arg(fileName(path), signer);
    else if (scope == "publisher") what = I18n::tr("all apps from %1").arg(signer);
    if (!destination.isEmpty()) what = I18n::tr("%1 to %2").arg(what, destination);
    QString line = QString("DECIDE\t%1\t%2\t%3").arg(allow ? "allow" : "block", scope, path);
    if (duration != "always" || !destination.isEmpty()) line += "\t" + duration;
    if (!destination.isEmpty()) line += "\t" + destination;
    const QString span = durationSpan(duration);
    enqueue(line, Request::Command,
            allow ? I18n::tr("Allow%1 saved for %2. The next connection attempt uses this rule.").arg(span, what)
                  : I18n::tr("Block%1 saved for %2. The next connection attempt uses this rule.").arg(span, what));
    poll();
}

// « hasta reiniciar», « durante 5 minutos» o nada (siempre): va pegado a la decisión en los mensajes.
QString FirewallClient::durationSpan(const QString &duration) {
    if (duration == "restart") return I18n::tr(" until restart");
    if (duration == "always") return {};
    return I18n::tr(" for %1").arg(describeDuration(duration.toLongLong()));
}

void FirewallClient::trustFolder(const QString &folder, const QString &name, bool allow, const QString &duration) {
    const QString where = QDir::toNativeSeparators(folder);
    QString line = QString("FOLDER\t%1\t%2\t%3").arg(allow ? "allow" : "block", where, name.isEmpty() ? "*" : name);
    if (duration != "always") line += "\t" + duration;
    const QString span = durationSpan(duration);
    QString message;
    if (name.isEmpty())
        message = allow ? I18n::tr("Every program in %1 can connect%2, also new builds there.").arg(where, span)
                        : I18n::tr("Every program in %1 stays blocked%2.").arg(where, span);
    else
        message = allow ? I18n::tr("%1 in %2 can connect%3, also new builds there.").arg(name, where, span)
                        : I18n::tr("%1 in %2 stays blocked%3.").arg(name, where, span);
    enqueue(line, Request::Command, message);
    poll();
}

void FirewallClient::removeRule(const QString &id) {
    const auto *r = ruleById(id);
    const QString what = r ? describe(*r) : fileName(id);
    enqueue("REMOVE\t" + id, Request::Command,
            I18n::tr("Rule removed for %1. The next connection will be blocked and ask again.").arg(what));
    poll();
}

void FirewallClient::setLocalNetwork(bool allow) {
    enqueue(QString("LAN\t%1").arg(allow ? "allow" : "ask"), Request::Command,
            allow ? I18n::tr("Local network connections no longer ask.")
                  : I18n::tr("Local network connections ask like any other."));
    poll();
}

void FirewallClient::setAsk(bool ask) {
    enqueue(QString("MODE\t%1").arg(ask ? "ask" : "off"), Request::Command,
            ask ? I18n::tr("Unknown applications are blocked until you decide.")
                : I18n::tr("Unknown applications can connect. Saved rules still apply."));
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
    // Reglas e historial, cuando toca (un poco antes de la hora, para no perder una vuelta por milisegundos).
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const auto due = [&](int every, qint64 last) { return forceFull_ || (every > 0 && now - last >= every - 250); };
    if (due(rulesMs_, rulesAt_)) {
        rulesAt_ = now;
        enqueue("RULES", Request::Rules);
    }
    if (due(activityMs_, activityAt_)) {
        activityAt_ = now;
        enqueue("ACTIVITY", Request::Activity);
    }
    forceFull_ = false;
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
    QByteArray compared = raw;
    if (request.kind == Request::Status) {
        // Los contadores de DNS de STATUS («names») cambian con cualquier consulta de la PC y la ventana no los usa:
        // contarlos como cambio rearmaba la ventana cada segundo sin motivo.
        QList<QByteArray> kept;
        for (const auto &line : raw.split('\n'))
            if (!line.startsWith("names\t")) kept << line;
        compared = kept.join('\n');
    }
    if (request.kind == Request::Command || compared != lastRaw_[slot]) {
        if (request.kind != Request::Command) lastRaw_[slot] = compared;
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
    forceFull_ = true; // al volver, todo de nuevo
    // Sin motor no hay datos vigentes: se vacía todo para no mostrar reglas o pedidos viejos como actuales.
    pending_.clear();
    rules_.clear();
    pathIndex_.clear();
    ++rulesVersion_;
    activity_.clear();
    while (!queue_.empty()) {
        if (queue_.front().kind == Request::Command) {
            --commandsInFlight_;
            emit commandFinished(false, I18n::tr("GateBouncer engine is not running. Nothing was changed."));
        }
        queue_.pop_front();
    }
    if (wasConnected) emit changed();
}

void FirewallClient::apply(const Request &request, const QStringList &lines) {
    const bool ok = !lines.isEmpty() && lines.first().startsWith("OK");
    if (request.kind == Request::Command) {
        --commandsInFlight_;
        const QString error = !ok && !lines.isEmpty() ? lines.first().section('\t', 1) : I18n::tr("No reply");
        emit commandFinished(ok, ok ? request.okMessage : error);
        // Una decisión cambia reglas y pedidos: se pide todo, también con la ventana escondida.
        forceFull_ = true;
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
            if (!knownPending_.contains(key(p.id))) {
                // El aviso cuenta las reglas de esa app: con la ventana escondida, las reglas se piden en la vuelta
                // siguiente en vez de esperar su turno.
                rulesAt_ = 0;
                emit newPending(p.id);
            }
        }
        knownPending_ = now;
        break;
    }
    case Request::Rules:
        ++rulesVersion_;
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
            if (r.scope == "folder") r.path = f.size() == 10 ? f[9] : QString(); // la carpeta
            rules_.push_back(r);
        }
        pathIndex_.clear();
        for (int i = 0; i < rules_.size(); ++i)
            if (rules_[i].destination.isEmpty() && !rules_[i].path.isEmpty() && !pathIndex_.contains(key(rules_[i].path)))
                pathIndex_.insert(key(rules_[i].path), i);
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
