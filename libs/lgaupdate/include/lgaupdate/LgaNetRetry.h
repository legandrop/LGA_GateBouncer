#pragma once

// Reintentos de red de las apps LGA: 3 reintentos, 5 segundos entre intentos.
//
// Regla dura de Lega (2026-11-04): en su PC corre GateBouncer, un firewall por aplicacion que
// BLOQUEA (no demora) el primer intento de cada programa sin regla y de cada destino nuevo. La
// decision de Lega en el aviso vale recien para el intento siguiente: sin reintentos, el pedido
// falla antes de que llegue a apretar Allow. Fuente de verdad de la regla:
// LGA_RepoTools/Docs/Convencion_Red_Reintentos.md.
//
// Pieza canonica de LGA_Base_QT_C_Py (libs/lgaupdate): las apps que no usan lgaupdate la copian
// IDENTICA para su propio codigo de red. Solo decide QUE se reintenta y CUANTO se espera; cada
// pedido sigue siendo de su dueno, que lo vuelve a mandar con QTimer::singleShot (nunca dormir el
// hilo de la interfaz) y deja cada intento en el log.

#include <QNetworkReply>
#include <QString>
#include <QVariant>

namespace LgaNetRetry {

/// Reintentos despues del primer intento: cuatro intentos en total.
constexpr int kRetries = 3;

/// Espera entre un intento y el siguiente.
constexpr int kDelayMs = 5000;

/// Solo para pruebas automaticas: con un valor >= 0, delayMs() lo devuelve en lugar de kDelayMs,
/// para no esperar 15 s por caso. El codigo de la app nunca lo toca.
inline int &delayMsOverrideForTests()
{
    static int value = -1;
    return value;
}

/// Espera a usar antes del proximo intento.
inline int delayMs()
{
    const int value = delayMsOverrideForTests();
    return value >= 0 ? value : kDelayMs;
}

/// `true` si el pedido que termino en `reply` se vuelve a mandar.
///
/// - Siempre los errores de conexion: rechazada o cortada, host o proxy que no aparece, timeout,
///   falla temporal de red, TLS cortado. Un bloqueo de GateBouncer cae aca.
/// - Los cortes de HTTP/2 a mitad del cuerpo (GitHub y los CDN lo usan): un RST_STREAM llega como
///   `ProtocolFailure` o como un error de servidor con status 200, y un GOAWAY como
///   `ContentReSendError` o `ProtocolUnknownError`. Una descarga cortada asi tiene que reanudar.
/// - Las respuestas transitorias del servidor: HTTP 408, 429 y 5xx (salvo 501).
/// - Nunca una respuesta definitiva (401, 403, 404...): si el servidor contesto, el firewall ya
///   dejo pasar.
/// - `cancelledOnPurpose` solo cuenta para `OperationCanceledError`, que lo da tanto el `abort()`
///   de quien cancela como el vencimiento de `setTransferTimeout()` (Qt no los distingue). La
///   cancelacion del USUARIO (o de la app al cerrarse) la mira quien llama ANTES de preguntar aca:
///   el status va primero a proposito, para que un `abort()` que el dueno hace sobre una respuesta
///   5xx se reintente.
inline bool shouldRetry(const QNetworkReply *reply, bool cancelledOnPurpose)
{
    if (!reply) {
        return false;
    }
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (status == 408 || status == 429 || (status >= 500 && status <= 599 && status != 501)) {
        return true;
    }
    switch (reply->error()) {
    case QNetworkReply::OperationCanceledError:
        return !cancelledOnPurpose;
    case QNetworkReply::ProtocolFailure:
    case QNetworkReply::ContentReSendError:
    case QNetworkReply::ProtocolUnknownError:
    case QNetworkReply::InternalServerError:
    case QNetworkReply::ServiceUnavailableError:
    case QNetworkReply::UnknownServerError:
    case QNetworkReply::ConnectionRefusedError:
    case QNetworkReply::RemoteHostClosedError:
    case QNetworkReply::HostNotFoundError:
    case QNetworkReply::TimeoutError:
    case QNetworkReply::SslHandshakeFailedError:
    case QNetworkReply::TemporaryNetworkFailureError:
    case QNetworkReply::NetworkSessionFailedError:
    case QNetworkReply::UnknownNetworkError:
    case QNetworkReply::ProxyConnectionRefusedError:
    case QNetworkReply::ProxyConnectionClosedError:
    case QNetworkReply::ProxyNotFoundError:
    case QNetworkReply::ProxyTimeoutError:
    case QNetworkReply::UnknownProxyError:
        return true;
    default:
        return false;
    }
}

/// Texto de log del intento `attempt` (1 = el primero): «intento 2 de 4».
inline QString attemptLabel(int attempt)
{
    return QStringLiteral("intento %1 de %2").arg(attempt).arg(kRetries + 1);
}

/// Tope total de intentos de un pedido, sumando todos sus servidores: corta una cadena de
/// redirects que falla en un servidor nuevo cada vez.
constexpr int kMaxAttempts = 10;

/// Cuenta de intentos de UN pedido, con todos sus redirects. GateBouncer pregunta por cada
/// servidor nuevo: una descarga de GitHub pasa por github.com y despues por el servidor de los
/// archivos, y cada uno puede quedar bloqueado en su primer intento. Por eso cada servidor en el
/// que el pedido falla tiene sus propios kRetries reintentos (la regla dice «cada destino nuevo
/// arranca su propia cuenta»), con kMaxAttempts como tope total.
///
/// Uso: reset() antes del primer intento; al fallar uno que shouldRetry() da por reintentable,
/// allowRetry(reply) dice si se manda otro (y ya lo cuenta). `reply->url()` es la URL final,
/// despues de los redirects que Qt siguio.
class Budget
{
public:
    void reset()
    {
        m_host.clear();
        m_retriesOnHost = 0;
        m_attempt = 1;
    }

    bool allowRetry(const QNetworkReply *reply)
    {
        const QString host = reply ? reply->url().host().toLower() : QString();
        if (host != m_host) {
            m_host = host;
            m_retriesOnHost = 0;
        }
        if (m_retriesOnHost >= kRetries || m_attempt >= kMaxAttempts) {
            return false;
        }
        ++m_retriesOnHost;
        ++m_attempt;
        return true;
    }

    /// Intento en curso, contando todos los servidores (1 = el primero).
    int attempt() const { return m_attempt; }

    /// Para la interfaz: el intento en curso sobre el servidor actual (1 = el primero en ese
    /// servidor), sobre kRetries + 1. Vuelve a empezar si el pedido pasa a fallar en otro servidor.
    int attemptOnHost() const { return m_retriesOnHost + 1; }

    /// Texto de log: «intento 3 (2 de 4 en objects.githubusercontent.com)». Antes de la primera
    /// falla todavia no hay servidor: «intento 1 de 4».
    QString label() const
    {
        if (m_host.isEmpty()) {
            return attemptLabel(m_attempt);
        }
        return QStringLiteral("intento %1 (%2 de %3 en %4)")
            .arg(m_attempt)
            .arg(attemptOnHost())
            .arg(kRetries + 1)
            .arg(m_host);
    }

private:
    QString m_host;
    int m_retriesOnHost = 0;
    int m_attempt = 1;
};

} // namespace LgaNetRetry
