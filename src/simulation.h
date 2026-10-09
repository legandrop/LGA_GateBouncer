#pragma once

#include <QDateTime>
#include <QMap>
#include <QObject>
#include <QSet>
#include <QVector>
#include <optional>
#include "data/activityhistory.h"
#include "assistance/ExplanationCoordinator.h"
#include "assistance/MockExplanationTransport.h"

namespace Gate {
enum class Policy { Ask, Allow, Block };
enum class Service { Available, UiClosed, Unavailable };
enum class EventKind { Attempt, Authorization, Traffic, Decision };
QString policyText(Policy policy);
QString eventText(EventKind kind);
QString relativeTime(qint64 seconds);
QString absoluteTime(qint64 seconds);
QString timestamp(qint64 seconds);
QDateTime sampleNow();

struct Process {
    QString id, name, publisher, path;
    Policy policy = Policy::Ask;
    bool running = false;
    qint64 attempt = -1, authorized = -1, traffic = -1;
    QString scope, duration;
    int ruleDays = 0;
    bool missing = false;
    QString signature, destination, protocol, initials;
    bool system = false;
};
struct Review {
    int scope = 0, duration = 0;
    bool expanded = false;
};
struct Rule {
    QString id, name;
    Policy policy = Policy::Ask;
    QString scope, source;
    qint64 last = -1;
    int days = 0;
    bool missing = false, active = true;
    QString duration = "Permanent";
};
struct Event {
    QString name;
    EventKind kind;
    qint64 age;
    QString destination, reason;
    QString id = {};
};
struct ImportRow {
    QString id, name;
    Policy policy;
    QString status, note;
    bool bandwidth = false;
};
struct Snapshot {
    QVector<Process> processes;
    QVector<Rule> rules;
    QVector<Event> events;
    QSet<QString> pending;
    QMap<QString, Review> reviews;
    bool importLoaded = false, importApplied = false;
    Data::HistoryState history;
};

class Simulation final : public QObject {
    Q_OBJECT
  public:
    explicit Simulation(QObject *parent = nullptr);
    const Snapshot &state() const { return data_; }
    const QVector<ImportRow> &sampleImport() const { return import_; }
    const Process *process(const QString &id) const;
    const Rule *rule(const QString &id) const;
    bool available() const { return enabled_ && service_ != Service::Unavailable; }
    void setEnabled(bool enabled);
    Service service() const { return service_; }
    quint64 epoch() const { return epoch_; }
    bool isPending(const QString &id) const { return data_.pending.contains(id); }
    Review review(const QString &id) const { return data_.reviews.value(id); }
    bool setReview(const QString &id, quint64 epoch, const Review &review);
    bool decide(const QString &id, quint64 epoch, Policy policy);
    bool editRule(const QString &id, quint64 epoch, Policy policy);
    bool activate(const QString &id, quint64 epoch, Policy policy);
    bool loadImport(quint64 epoch);
    bool resetImport(quint64 epoch);
    bool applyImport(quint64 epoch);
    QVector<Rule> cleanupCandidates(int days) const;
    bool cleanup(const QSet<QString> &ids, int days, quint64 epoch);
    bool restore(quint64 epoch);
    bool hasBackup() const { return backup_.has_value(); }
    void setService(Service service);
    void reset();
  signals:
    void changed();
    void invalidated();
    void requestResolved(const QString &id);

  private:
    bool writable(quint64 epoch) const { return available() && epoch == epoch_; }
    void recordDecision(const QString &name, const QString &reason);
    Snapshot data_;
    QVector<ImportRow> import_;
    std::optional<Snapshot> backup_;
    Service service_ = Service::Available;
    quint64 epoch_ = 0;
    quint64 eventSequence_ = 0;
    bool enabled_ = false;
    Data::ActivityHistory history_;
    void recordHistory(const Event &event);
};

enum class ExplanationState { Idle, Loading, Known, Unclear, Error };
class Explanation final : public QObject {
    Q_OBJECT
  public:
    explicit Explanation(Simulation *model);
    bool configured() const { return coordinator_.configured(); }
    bool consent() const { return coordinator_.consent(); }
    bool automatic() const { return coordinator_.automatic(); }
    QString visibleId() const { return visible_; }
    ExplanationState status() const;
    quint64 generation() const { return coordinator_.binding().generation; }
    QString text() const;
    QString problem() const;
    QString disclosure() const { return coordinator_.disclosure(); }
    QString disclaimer() const { return coordinator_.disclaimer(); }
    void configure(bool on);
    void setConsent(bool on);
    void setAutomatic(bool on);
    void setFixture(ExplanationState fixture);
    ExplanationState fixture() const { return fixture_; }
    bool open(const QString &id);
    void close();
    bool start();
    void cancel();
    bool complete(const QString &id, quint64 generation, quint64 epoch, ExplanationState result);
  signals:
    void changed();

  private:
    Assistance::RequestContext context() const;
    Simulation *model_;
    Assistance::MockExplanationTransport transport_;
    Assistance::ExplanationCoordinator coordinator_;
    QString visible_;
    ExplanationState fixture_ = ExplanationState::Known;
    quint64 demoGeneration_ = 1;
};
} // namespace Gate
