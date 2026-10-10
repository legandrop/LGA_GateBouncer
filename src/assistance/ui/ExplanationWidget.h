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
    QString observedName_; // Sólo presentación; nunca inicia ni aprueba la consulta.
    QLineEdit *product_,*publisher_;
    QLabel *text_,*state_,*destination_,*localSummary_,*localDetails_,*networkDetails_;
    QPushButton *approve_,*start_,*cancel_;
    QProgressBar *progress_;
    QWidget *citations_,*details_;
};
}
