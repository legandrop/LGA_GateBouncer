#pragma once
#include "GeneralSession.h"
#include <QFrame>
class QLabel;class QLineEdit;class QPushButton;class QProgressBar;class QVBoxLayout;
namespace Gate::Assistance::Ui {
class ExplanationWidget final : public QFrame {
    Q_OBJECT
public:
    using Binding=std::function<std::optional<General::FullBinding>()>;
    ExplanationWidget(GeneralSession*,Binding,const QString& suggestedProduct,QWidget* parent=nullptr);
    void setSession(GeneralSession*);
private:
    void refresh();
    QPointer<GeneralSession> session_;
    Binding binding_;
    QLineEdit *product_,*publisher_;
    QLabel *text_,*state_;
    QPushButton *approve_,*start_,*cancel_;
    QProgressBar *progress_;
    QWidget* citations_;
};
}
