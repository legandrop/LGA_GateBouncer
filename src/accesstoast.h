#pragma once
// Aviso fijo de una solicitud de acceso, como el aviso de disco de Mighty Tools: ventana propia sin marco, siempre
// encima y sin robar el foco, abajo a la derecha de la pantalla. Queda hasta que se decide o se cierra; cerrarlo no
// decide nada y la app sigue bloqueada en Pending.
#include <QPointer>
#include <QScreen>
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
        // El pedido: la ruta, o en modo por destino «ruta|dirección» (un pedido por cada destino nuevo).
        QString id;
        bool perDestination = false;
        int serverRules = 0; // modo por destino: cuántos servidores ya tienen regla; 0 si no se sabe
        QString path;
        QString signer; // vacío: sin firma válida, sólo «This file only»
        int attempts = 0;
        int othersWaiting = 0;
        bool canDecide = true;
        QString remote, host; // destino del último intento; host vacío si no se sabe el nombre
        int port = 0, protocol = 0;
        QString known;      // lo que dice el catálogo de apps conocidas; vacío si no está
        QString launchedBy; // el programa que la lanzó (nombre de archivo); vacío: no se muestra la fila
    };

    explicit AccessToast(QWidget *parent = nullptr);
    // Con el mismo pedido sólo actualiza contadores y botones: los desplegables conservan lo elegido.
    void setRequest(const Request &request);
    QString id() const { return request_.id; }
    QString path() const { return request_.path; }
    // Abajo a la derecha de la pantalla, o donde el usuario lo dejó la última vez. Siempre entero dentro del área
    // visible: nunca debajo de la barra de tareas, aunque crezca con la explicación.
    void placeOn(QScreen *screen);
    // Se ignora si el aviso ya muestra otro pedido: una respuesta tardía nunca cae sobre otra solicitud.
    void setExplanation(const QString &id, const Explanation &explanation);

  signals:
    // duration: "always", "restart" o segundos ("900"). destination: vacío para la app entera; si no, el destino.
    void decided(const QString &id, bool allow, const QString &scope, const QString &duration,
                 const QString &destination);
    void explainRequested(const QString &id);
    void settingsRequested();
    void dismissed(const QString &id);
    void openRequested();
    void pendingListRequested();

  protected:
    void paintEvent(QPaintEvent *event) override;
    // Se arrastra desde cualquier parte que no sea un control y se ensancha desde los bordes izquierdo y derecho.
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void leaveEvent(QEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    bool eventFilter(QObject *watched, QEvent *event) override;

  private:
    void rebuildScopes();
    void rebuildTargets();
    // Una regla por carpeta es para la app entera: el destino queda en «Any destination» y se explica qué cubre.
    bool folderScope() const;
    void syncFolderScope();
    void applyWidth(int width);
    void keepInside();
    void remember();
    int edgeAt(const QPoint &pos) const;
    void updateCounters();
    void renderExplanation();
    void renderDestination();
    void renderKnown();
    // Recalcula anchos y altos de los textos que se parten, los recortes y la fila de la regla, y ajusta el alto.
    void relayout();
    void layoutChoices();

    Request request_;
    // Los botones se habilitan un instante después de mostrar otra app: un clic que iba al aviso anterior (doble clic,
    // clic tardío) no decide sobre la siguiente.
    bool armed_ = false;
    // Cabecera y datos.
    QLabel *icon_ = nullptr, *title_ = nullptr, *body_ = nullptr;
    QWidget *warnBox_ = nullptr, *infoBox_ = nullptr;
    QLabel *warn_ = nullptr, *info_ = nullptr;
    QLabel *signature_ = nullptr, *signatureDetail_ = nullptr; // firma y, debajo, la carpeta del programa
    QLabel *wantsKey_ = nullptr, *destination_ = nullptr, *destinationDetail_ = nullptr;
    QLabel *launchedKey_ = nullptr, *launched_ = nullptr;
    QWidget *knownBox_ = nullptr;
    QLabel *knownPill_ = nullptr, *knownText_ = nullptr;
    // Regla y decisión.
    QWidget *choices_ = nullptr;
    QComboBox *scope_ = nullptr, *duration_ = nullptr, *target_ = nullptr;
    QLabel *folderNote_ = nullptr; // con una opción de carpeta: la carpeta entera y qué cubre
    QLabel *footer_ = nullptr;
    QPushButton *block_ = nullptr, *allow_ = nullptr;
    bool targetChosen_ = false; // el usuario tocó «Destination»
    QString chosenTarget_;      // lo que eligió ahí (vacío: Any destination), para volver a eso al dejar una carpeta
    // Esquina de abajo a la derecha, en coordenadas de pantalla: el aviso crece hacia arriba desde ahí.
    QPoint anchor_;
    bool anchored_ = false;
    int width_ = 0;
    int edge_ = 0; // -1 izquierda, 1 derecha mientras se ensancha
    bool dragging_ = false;
    QPoint pressGlobal_, pressAnchor_;
    int pressWidth_ = 0;
    QPointer<QScreen> screen_; // la pantalla puede desaparecer (monitor desconectado, sesión remota)
    // Tarjeta de la explicación con IA.
    Explanation explanation_;
    bool detailsOpen_ = false;
    QWidget *explainBox_ = nullptr, *spinner_ = nullptr, *more_ = nullptr;
    QLabel *explainStatus_ = nullptr, *suggestion_ = nullptr, *what_ = nullptr;
    QLabel *why_ = nullptr, *reason_ = nullptr, *risk_ = nullptr;
    QLabel *whyHead_ = nullptr, *reasonHead_ = nullptr, *riskHead_ = nullptr;
    QLabel *explainFoot_ = nullptr;
    QPushButton *details_ = nullptr, *explainAction_ = nullptr, *settingsLink_ = nullptr;
    QTimer *spin_ = nullptr;
};

} // namespace Gate
