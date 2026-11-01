#pragma once
// Aviso fijo de una solicitud de acceso, como el aviso de disco de Mighty Tools: ventana propia sin marco, siempre
// encima y sin robar el foco, abajo a la derecha de la pantalla. Queda hasta que se decide o se cierra; cerrarlo no
// decide nada y la app sigue bloqueada en Pending.
#include <QWidget>

class QComboBox;
class QLabel;
class QPushButton;
class QScreen;

namespace Gate {

class AccessToast final : public QWidget {
    Q_OBJECT
  public:
    struct Request {
        QString path;
        QString signer; // vacío: sin firma válida, sólo «This file only»
        int attempts = 0;
        int othersWaiting = 0;
        bool canDecide = true;
    };

    explicit AccessToast(QWidget *parent = nullptr);
    // Con la misma ruta sólo actualiza contadores y botones: el desplegable conserva lo elegido.
    void setRequest(const Request &request);
    QString path() const { return request_.path; }
    void placeOn(QScreen *screen);

  signals:
    void decided(const QString &path, bool allow, const QString &scope);
    void dismissed(const QString &path);
    void openRequested();
    void pendingListRequested();

  protected:
    void paintEvent(QPaintEvent *event) override;

  private:
    void rebuildScopes();
    void updateCounters();

    Request request_;
    // Los botones se habilitan un instante después de mostrar otra app: un clic que iba al aviso anterior (doble clic,
    // clic tardío) no decide sobre la siguiente.
    bool armed_ = false;
    QLabel *icon_ = nullptr, *title_ = nullptr, *signature_ = nullptr, *signatureMark_ = nullptr, *path_ = nullptr;
    QLabel *note_ = nullptr, *footer_ = nullptr;
    QComboBox *scope_ = nullptr;
    QPushButton *block_ = nullptr, *allow_ = nullptr;
};

} // namespace Gate
