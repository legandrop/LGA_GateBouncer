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
        bool localNetwork = true; // la red local pasa sin preguntar
        qint64 started = 0;
        QString lastError;
    };
    struct PendingItem {
        QString path, remote;
        qint64 first = 0, last = 0;
        int attempts = 0, port = 0, protocol = 0;
        QString signer; // vacío: sin firma embebida válida (la verifica el motor)
        QString host;   // el nombre que la app resolvió para esa dirección; vacío si no se sabe
        // Modo por destino: la decisión es sobre este destino. Un pedido por dirección nueva.
        bool perDestination = false;
        QString id; // la ruta, o «ruta|dirección» en modo por destino
    };
    // Alcances del motor: "path" (ruta exacta), "app" (firmante + nombre del exe, cualquier carpeta), "publisher"
    // (todo lo del firmante), "folder" (todo exe dentro de una carpeta, o sólo los que se llaman name) y "covered" (una
    // ruta que una regla app, publisher o folder ya permitió o bloqueó).
    struct RuleItem {
        QString path; // path y covered: la ruta; folder: la carpeta; vacío en app y publisher
        bool allow = true;
        qint64 created = 0, lastBlock = 0;
        QString scope = "path", signer, name, id; // id: lo que se manda en REMOVE
        qint64 expires = 0; // 0 permanente, -1 hasta reiniciar el motor, si no el momento Unix en que vence
        QString destination; // vacío: la app entera; si no, un host, «*.dominio» o una IP
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
    // Incluye las filas "covered": para contar o listar reglas, saltearlas.
    const QVector<RuleItem> &rules() const { return rules_; }
    int ruleCount() const;
    const QVector<ActivityItem> &activity() const { return activity_; }
    // El primer pedido de esa app (cualquier destino).
    const PendingItem *pendingFor(const QString &path) const;
    const PendingItem *pendingById(const QString &id) const;
    // Regla de la app entera de esa ruta o cobertura de una regla por firma (las reglas por destino no cuentan).
    const RuleItem *ruleFor(const QString &path) const;
    // La regla por carpeta que tiene adentro a esa ruta, o nada. Por texto, para mostrar: el motor decide por la ruta
    // final del archivo.
    const RuleItem *folderRuleFor(const QString &path) const;
    const RuleItem *ruleById(const QString &id) const;
    bool busy() const { return commandsInFlight_ > 0; }

    // scope: "path", "app" o "publisher". La firma la verifica el motor, no la ventana. También "folder:<carpeta>"
    // (todo programa de esa carpeta) o "foldername:<carpeta>" (los que se llaman como este): una regla por carpeta, que
    // es para la app entera, así que ignora destination.
    // duration: "always", "restart" (hasta que el motor se reinicie) o segundos ("900").
    // destination: vacío para la app entera; si no, sólo ese destino (la app pasa a modo por destino).
    void decide(const QString &path, bool allow, const QString &scope = "path", const QString &duration = "always",
                const QString &destination = {});
    // Regla por carpeta: todo exe dentro de folder y sus subcarpetas, o sólo los que se llaman name (vacío: todos). El
    // motor valida la carpeta (ni raíces de unidad ni carpetas del sistema o del usuario) y responde el motivo.
    void trustFolder(const QString &folder, const QString &name, bool allow = true, const QString &duration = "always");
    void removeRule(const QString &id);
    void setAsk(bool ask);
    void setLocalNetwork(bool allow);
    void refreshNow();

    static QString fileName(const QString &path);
    static QString protocolName(int protocol);
    // "Internet", "Local network", "Tailscale" o "This PC"; vacío si no es una dirección.
    static QString destinationKind(const QString &address);
    // Texto de una regla por firma o por carpeta: "any version of node.exe from OpenJS Foundation", "all apps in
    // C:\Portable\LGA_DayTrace".
    static QString describe(const RuleItem &rule);
    // Igual que el motor: un firmante de Microsoft no admite «All apps from».
    static bool publisherRuleAllowed(const QString &signer);
    // "15 minutes", "1 hour".
    static QString describeDuration(qint64 seconds);
    // Lo que le queda a una regla: vacío si es permanente, "until restart" o "12 min left".
    static QString remaining(const RuleItem &rule);

  signals:
    void changed();
    void newPending(const QString &id);
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
    bool waiting_ = false, active_ = false;
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
