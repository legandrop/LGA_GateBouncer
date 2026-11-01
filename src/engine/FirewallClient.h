#pragma once
// Cliente del motor sin driver (GateBouncerEngine.exe) por su canal local.
// Pregunta el estado cada segundo y manda las decisiones; nunca filtra nada por sí mismo.
class QLocalSocket;
#include <QObject>
#include <QSet>
#include <QTimer>
#include <QVector>
#include <deque>

namespace Gate {

class FirewallClient final : public QObject {
    Q_OBJECT
  public:
    struct Status {
        bool connected = false, ask = true, dynamic = false, allApps = true, control = false;
        qint64 started = 0;
        QString lastError;
    };
    struct PendingItem {
        QString path, remote;
        qint64 first = 0, last = 0;
        int attempts = 0, port = 0, protocol = 0;
    };
    struct RuleItem {
        QString path;
        bool allow = true;
        qint64 created = 0, lastBlock = 0;
    };
    struct ActivityItem {
        qint64 time = 0;
        QString kind, remote, path;
        int port = 0, protocol = 0;
    };

    explicit FirewallClient(QObject *parent = nullptr);
    void setActive(bool active);
    bool active() const { return active_; }
    const Status &status() const { return status_; }
    const QVector<PendingItem> &pending() const { return pending_; }
    const QVector<RuleItem> &rules() const { return rules_; }
    const QVector<ActivityItem> &activity() const { return activity_; }
    const PendingItem *pendingFor(const QString &path) const;
    const RuleItem *ruleFor(const QString &path) const;
    bool busy() const { return commandsInFlight_ > 0; }

    void decide(const QString &path, bool allow);
    void removeRule(const QString &path);
    void setAsk(bool ask);
    void refreshNow();

    static QString fileName(const QString &path);
    static QString protocolName(int protocol);

  signals:
    void changed();
    void newPending(const QString &path);
    void commandFinished(bool ok, const QString &message);

  private:
    struct Request {
        QString line;
        enum Kind { Status, Pending, Rules, Activity, Command } kind;
        QString okMessage;
    };
    void enqueue(const QString &line, Request::Kind kind, const QString &okMessage = {});
    void poll();
    void sendNext();
    void onReadyRead();
    void onDisconnected();
    void apply(const Request &request, const QStringList &lines);

    QLocalSocket *socket_ = nullptr; // hijo de este objeto; fuera del header para no exigir QtNetwork a quien lo incluye
    QTimer timer_;
    std::deque<Request> queue_;
    bool waiting_ = false, active_ = false, firstPending_ = true;
    int commandsInFlight_ = 0;
    QByteArray buffer_;
    QByteArray lastRaw_[4];
    Status status_;
    QVector<PendingItem> pending_;
    QVector<RuleItem> rules_;
    QVector<ActivityItem> activity_;
    QSet<QString> knownPending_;
};

} // namespace Gate
