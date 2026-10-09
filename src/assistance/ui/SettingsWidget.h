#pragma once
#include "GeneralSession.h"
#include <QFrame>
class QLabel;class QLineEdit;class QPushButton;class QComboBox;class QProgressBar;
namespace Gate::Assistance::Ui {
class SettingsWidget final : public QFrame {
    Q_OBJECT
public:
    explicit SettingsWidget(GeneralSession*,QWidget* parent=nullptr);
signals:
    void connectRequested();
private:
    void refresh();
    QPointer<GeneralSession> session_;
    QLabel *status_,*model_,*web_,*problem_;
    QLineEdit *key_;
    QComboBox *mode_;
    QProgressBar *progress_;
    QPushButton *connect_,*refresh_,*store_,*forget_,*selectSearch_,*grantModel_,*revokeModel_,*grantWeb_,*revokeWeb_;
};
}
