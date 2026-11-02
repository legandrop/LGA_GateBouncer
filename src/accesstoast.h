#pragma once
// Aviso fijo de una solicitud de acceso, como el aviso de disco de Mighty Tools: ventana propia sin marco, siempre
// encima y sin robar el foco, abajo a la derecha de la pantalla. Queda hasta que se decide o se cierra; cerrarlo no
// decide nada y la app sigue bloqueada en Pending.
#include <QWidget>

class QComboBox;
class QLabel;
class QPushButton;
class QScreen;
class QTimer;

namespace Gate {

class AccessToast final : public QWidget {
    Q_OBJECT
  public:
    // Explicación con IA: sólo ayuda a decidir. Ofrecida, sin key, pidiendo, lista o fallida.
    struct Explanation {
        enum State { Offer, NoKey, Working, Ready, Failed } state = Offer;
        QString what, why, risk, suggestion, reason, model, error;
    };
    struct Request {
        QString path;
        QString signer; // vacío: sin firma válida, sólo «This file only»
        int attempts = 0;
        int othersWaiting = 0;
        bool canDecide = true;
        QString remote, host; // destino del último intento; host vacío si no se sabe el nombre
        int port = 0, protocol = 0;
    };

    explicit AccessToast(QWidget *parent = nullptr);
    // Con la misma ruta sólo actualiza contadores y botones: el desplegable conserva lo elegido.
    void setRequest(const Request &request);
    QString path() const { return request_.path; }
    void placeOn(QScreen *screen);
    // Se ignora si el aviso ya muestra otra app: una respuesta tardía nunca cae sobre otra solicitud.
    void setExplanation(const QString &path, const Explanation &explanation);

  signals:
    // duration: "always", "restart" o segundos ("900").
    void decided(const QString &path, bool allow, const QString &scope, const QString &duration);
    void explainRequested(const QString &path);
    void settingsRequested();
    void dismissed(const QString &path);
    void openRequested();
    void pendingListRequested();

  protected:
    void paintEvent(QPaintEvent *event) override;

  private:
    void rebuildScopes();
    void updateCounters();
    void renderExplanation();
    void renderDestination();

    Request request_;
    // Los botones se habilitan un instante después de mostrar otra app: un clic que iba al aviso anterior (doble clic,
    // clic tardío) no decide sobre la siguiente.
    bool armed_ = false;
    QLabel *icon_ = nullptr, *title_ = nullptr, *signature_ = nullptr, *signatureMark_ = nullptr, *path_ = nullptr;
    QLabel *note_ = nullptr, *footer_ = nullptr;
    QLabel *destination_ = nullptr, *destinationDetail_ = nullptr;
    QComboBox *scope_ = nullptr, *duration_ = nullptr;
    Explanation explanation_;
    QScreen *screen_ = nullptr;
    QWidget *explainBox_ = nullptr;
    QLabel *explainStatus_ = nullptr, *what_ = nullptr, *why_ = nullptr, *risk_ = nullptr, *suggestion_ = nullptr;
    QLabel *explainFoot_ = nullptr;
    QPushButton *explainAction_ = nullptr;
    QTimer *dots_ = nullptr;
    int dotCount_ = 0;
    QPushButton *block_ = nullptr, *allow_ = nullptr;
};

} // namespace Gate
