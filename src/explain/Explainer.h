#pragma once
// Explicación con IA de una app bloqueada: qué es, por qué se conecta y una sugerencia. Sólo ayuda a decidir: nunca
// permite ni bloquea nada, y su respuesta se trata como texto no confiable (se valida, se recorta y se muestra plano).
//
// Lo que se manda al proveedor (NVIDIA o Anthropic, según el modelo elegido) son datos locales del ejecutable: nombre,
// carpeta (con la carpeta del usuario reemplazada por %USERPROFILE%), firma verificada por el motor, datos de versión
// del archivo y el destino público que intentó. Nunca el contenido del archivo, la línea de comandos, el nombre de la
// cuenta ni direcciones de la red local.
#include "KeyStore.h"
#include <QObject>
#include <QPointer>
#include <QSet>
#include <QString>
#include <QStringList>

namespace Gate::Explain {

// El proveedor sale del modelo: los de Anthropic empiezan con «claude-», el resto es del catálogo de NVIDIA.
Provider providerOf(const QString &model);
QString providerName(Provider provider);

struct Facts {
    QString path; // ruta local: no se manda tal cual
    QString fileName, folder, signer, product, description, company, version, destination;
    QString serverName; // el nombre DNS que resolvió la app, sólo con destino público
    int attempts = 0;
};

struct Answer {
    QString what, why, risk, suggestion /* allow, block o either */, reason, model;
};

struct Settings {
    QString model;
    QString language; // "en" o "es"
    bool automatic = false;
    bool consent = false; // el usuario aceptó qué se manda al proveedor del modelo elegido (se guarda por proveedor)
    static Settings load();
    void save() const;
    static void saveModel(const QString &model); // sólo el modelo: no toca el consentimiento de ningún proveedor
    static QStringList models();
    static QString defaultModel();
    static QString languageName(const QString &code);
};

// Datos locales del ejecutable. remote: la dirección que intentó; sólo se incluye si es pública, y con ella host (el
// nombre que la app resolvió para esa dirección).
Facts collectFacts(const QString &path, const QString &signer, const QString &remote, int port, int protocol,
                   int attempts, const QString &host = {});

// Partes sincrónicas, compartidas con la sonda de comparación de modelos. extras: campos opcionales del proveedor
// (razonamiento apagado en NVIDIA, modelo de respaldo ante un rechazo en Anthropic); sin ellos si el pedido falla.
QByteArray buildRequest(const Facts &facts, const QString &model, const QString &language, bool extras);
struct HttpResult {
    int status = 0;
    QByteArray body;
    QString error;
    qint64 milliseconds = 0;
};
// Pedido HTTPS al host fijo del proveedor (integrate.api.nvidia.com o api.anthropic.com): TLS 1.2+, sin
// redirecciones, plazo total y tope de tamaño.
HttpResult providerRequest(Provider provider, const char *method, const wchar_t *path, const QByteArray &body,
                           const std::string &key, int deadlineMs);
bool parseAnswer(const QByteArray &body, Answer &answer, QString &error);
// Recorridos de QA: respuesta fija, sin red ni key (variable GATEBOUNCER_QA_EXPLAIN).
bool qaFixture();
// Pedido completo con la key guardada: arma, manda (y reintenta sin extras si el modelo los rechaza) y valida.
bool explainNow(const Facts &facts, const QString &model, const QString &language, Answer &answer, QString &error,
                qint64 *milliseconds = nullptr);

class Explainer final : public QObject {
    Q_OBJECT
  public:
    explicit Explainer(QObject *parent = nullptr);
    // Pide la explicación en otro hilo. Devuelve false si ya hay una en curso para esa ruta o se llegó al tope diario.
    bool request(const Facts &facts, QString &error);
    bool busy(const QString &path) const;
    const Answer *cached(const QString &path) const;

  signals:
    void finished(const QString &path, bool ok, const Gate::Explain::Answer &answer, const QString &error);

  private:
    QSet<QString> running_;
    QHash<QString, Answer> cache_; // por ruta, modelo e idioma: la misma app no se pregunta dos veces
    QString cacheKey(const QString &path) const;
};

} // namespace Gate::Explain

Q_DECLARE_METATYPE(Gate::Explain::Answer)
