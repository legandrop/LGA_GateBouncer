#pragma once
#include "GeneralSession.h"
#include <QObject>
#include <QPointer>
#include <QThread>

namespace Gate { class MainWindow; }
namespace Gate::Assistance::Ui {
class GeneralConnection final : public QObject {
    Q_OBJECT
public:
    explicit GeneralConnection(MainWindow&);
    ~GeneralConnection() override;
    void close();
    bool idle() const;
signals:
    void failed(const QString&);
private:
    void connectBroker();
    void synchronizePending();
    struct LaunchResult;
    struct SettingsView;
    QPointer<MainWindow> window_;
    QThread* worker_=nullptr;
    std::shared_ptr<LaunchResult> launch_;
    std::shared_ptr<SettingsView> settings_;
    std::uint64_t generation_=0;
    bool closed_=false;
};
}
