#include "ProviderAdapters.h"
#include "../WinHttpCompatibility.h"
#include "../broker/BrokerPrimitives.h"
#include "ProviderPolicy.h"
#include "StrictJson.h"
#include <QCoreApplication>
#include <QThread>
#include <QTimer>
#include <array>
#include <cstring>
#include <winhttp.h>
namespace Gate::Assistance::Retrieval {
    struct WinHttpGetTransport::Job final : QObject, std::enable_shared_from_this<Job> {
        Endpoint endpoint;
        Completion completion;
        HttpReply reply;
        RequestSpec spec;
        HINTERNET session = nullptr, connection = nullptr, request = nullptr;
        QTimer deadline, drain;
        std::array<char, 4096> chunk{};
        std::optional<quint64> length;
        enum class Phase { New, Sending, Headers, Reading, Closing, Done } phase = Phase::New;
        bool registered = false, delivered = false;
        std::shared_ptr<Job> keep;
        Job() {
            deadline.setSingleShot(true);
            drain.setSingleShot(true);
        }
        ~Job() {
            if (connection)
                WinHttpCloseHandle(connection);
            if (session)
                WinHttpCloseHandle(session);
        }
        static void CALLBACK notify(HINTERNET, DWORD_PTR context, DWORD status, void *data,
                                    DWORD bytes) {
            auto *raw = reinterpret_cast<Job *>(context);
            if (!raw)
                return;
            auto self = raw->shared_from_this();
            DWORD value = 0;
            if (status == WINHTTP_CALLBACK_STATUS_READ_COMPLETE)
                value = bytes;
            else if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR && data &&
                     bytes == sizeof(WINHTTP_ASYNC_RESULT))
                value = static_cast<WINHTTP_ASYNC_RESULT *>(data)->dwError;
            QMetaObject::invokeMethod(
                self.get(), [self, status, value] { self->event(status, value); },
                Qt::QueuedConnection);
        }
        bool option(HINTERNET h, DWORD key, void *value, DWORD size) {
            return WinHttpSetOption(h, key, value, size);
        }
        void arm(qint64 ms) {
            auto weak = weak_from_this();
            connect(&deadline, &QTimer::timeout, this, [weak] {
                if (auto j = weak.lock())
                    j->end(Failure::Timeout);
            });
            connect(&drain, &QTimer::timeout, this, [weak] {
                if (auto j = weak.lock()) {
                    j->deliver();
                    QCoreApplication::exit(20);
                }
            });
            deadline.start(int(ms));
        }
        bool prepare() {
            session = WinHttpOpen(
                L"LGA_GateBouncer/0 (https://github.com/legandrop/LGA_GateBouncer) WinHTTP",
                WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS,
                WINHTTP_FLAG_ASYNC);
            if (!session)
                return false;
            BOOL yes = TRUE;
            DWORD one = 1, tls = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
            FailedConnectionRetries retries{0, 0};
            if (!option(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &tls, sizeof(tls)) ||
                !option(session, WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK, &yes,
                        sizeof(yes)) ||
                !option(session, FailedConnectionRetriesOption, &retries, sizeof(retries)) ||
                !option(session, DisableGlobalPoolingOption, &yes, sizeof(yes)) ||
                !option(session, WINHTTP_OPTION_CONNECT_RETRIES, &one, sizeof(one)) ||
                !WinHttpSetTimeouts(session, 3000, 3000, 3000, 3000))
                return false;
            connection = WinHttpConnect(session, spec.host.toStdWString().c_str(), 443, 0);
            if (!connection)
                return false;
            request = WinHttpOpenRequest(connection, L"GET", spec.path.toStdWString().c_str(),
                                         nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         WINHTTP_FLAG_SECURE);
            if (!request)
                return false;
            DWORD_PTR context = reinterpret_cast<DWORD_PTR>(this);
            if (!option(request, WINHTTP_OPTION_CONTEXT_VALUE, &context, sizeof(context)))
                return false;
            if (WinHttpSetStatusCallback(request, &notify,
                                         WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS |
                                             WINHTTP_CALLBACK_FLAG_HANDLES |
                                             WINHTTP_CALLBACK_FLAG_SECURE_FAILURE,
                                         0) == WINHTTP_INVALID_STATUS_CALLBACK)
                return false;
            registered = true;
            DWORD disabled = WINHTTP_DISABLE_AUTHENTICATION | WINHTTP_DISABLE_COOKIES |
                             WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_KEEP_ALIVE,
                  redirects = WINHTTP_OPTION_REDIRECT_POLICY_NEVER, headers = 8192,
                  autologon = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH,
                  revocation = WINHTTP_ENABLE_SSL_REVOCATION;
            if (!option(request, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)) ||
                !option(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirects, sizeof(redirects)) ||
                !option(request, WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE, &headers,
                        sizeof(headers)) ||
                !option(request, WINHTTP_OPTION_AUTOLOGON_POLICY, &autologon, sizeof(autologon)) ||
                !option(request, WINHTTP_OPTION_ENABLE_FEATURE, &revocation, sizeof(revocation)) ||
                !option(request, WINHTTP_OPTION_CLIENT_CERT_CONTEXT, WINHTTP_NO_CLIENT_CERT_CONTEXT,
                        0))
                return false;
            for (const auto &header : spec.headers) {
                const auto h = (header + "\r\n").toStdWString();
                if (!WinHttpAddRequestHeaders(request, h.c_str(), DWORD(h.size()),
                                              WINHTTP_ADDREQ_FLAG_ADD |
                                                  WINHTTP_ADDREQ_FLAG_REPLACE))
                    return false;
            }
            return noAuthentication(spec);
        }
        std::optional<QString> header(DWORD key) {
            std::array<wchar_t, 4097> b{};
            DWORD bytes = DWORD(b.size() * sizeof(wchar_t));
            if (!WinHttpQueryHeaders(request, key, WINHTTP_HEADER_NAME_BY_INDEX, b.data(), &bytes,
                                     WINHTTP_NO_HEADER_INDEX)) {
                if (GetLastError() == ERROR_WINHTTP_HEADER_NOT_FOUND)
                    return QString();
                return {};
            }
            return QString::fromWCharArray(b.data());
        }
        void send() {
            keep = shared_from_this();
            phase = Phase::Sending;
            if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    WINHTTP_NO_REQUEST_DATA, 0, 0,
                                    reinterpret_cast<DWORD_PTR>(this)))
                end(Failure::TransportUnavailable);
        }
        void readNext() {
            if (phase == Phase::Reading && request &&
                !WinHttpReadData(request, chunk.data(), DWORD(chunk.size()), nullptr))
                end(Failure::TransportUnavailable);
        }
        void event(DWORD status, DWORD value) {
            if (status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) {
                drain.stop();
                phase = Phase::Done;
                deliver();
                keep.reset();
                return;
            }
            if (phase == Phase::Closing || phase == Phase::Done)
                return;
            switch (status) {
            case WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE:
                phase = Phase::Headers;
                if (!WinHttpReceiveResponse(request, nullptr))
                    end(Failure::TransportUnavailable);
                break;
            case WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE: {
                DWORD code = 0, bytes = sizeof(code);
                if (!WinHttpQueryHeaders(
                        request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &code, &bytes, WINHTTP_NO_HEADER_INDEX)) {
                    end(Failure::TransportUnavailable);
                    break;
                }
                reply.status = int(code);
                if (code == 429 || code == 503) {
                    auto retry = header(WINHTTP_QUERY_RETRY_AFTER);
                    auto n = retry ? decimal(retry->toLatin1()) : std::nullopt;
                    reply.retryAfter = n && *n <= 3600 ? quint32(*n) : 3601;
                    end(Failure::RateLimited);
                    break;
                }
                if (code != 200) {
                    end(Failure::TransportUnavailable);
                    break;
                }
                auto encoding = header(WINHTTP_QUERY_CONTENT_ENCODING),
                     content = header(WINHTTP_QUERY_CONTENT_TYPE),
                     size = header(WINHTTP_QUERY_CONTENT_LENGTH);
                if (!encoding ||
                    (!encoding->isEmpty() && encoding->compare("identity", Qt::CaseInsensitive)) ||
                    !content ||
                    content->section(';', 0, 0).trimmed().compare("application/json",
                                                                  Qt::CaseInsensitive) ||
                    !size) {
                    end(Failure::InvalidResponse);
                    break;
                }
                if (!size->isEmpty()) {
                    auto n = decimal(size->toLatin1());
                    if (!n || *n > 131072) {
                        end(Failure::InvalidResponse);
                        break;
                    }
                    length = *n;
                }
                phase = Phase::Reading;
                readNext();
                break;
            }
            case WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
                if (value > chunk.size() || reply.body.size() + quint64(value) > 131072) {
                    end(Failure::InvalidResponse);
                    break;
                }
                if (value) {
                    reply.body.append(chunk.data(), int(value));
                    readNext();
                } else
                    end(length && *length != quint64(reply.body.size()) ? Failure::InvalidResponse
                                                                        : Failure::None);
                break;
            case WINHTTP_CALLBACK_STATUS_SECURE_FAILURE:
                end(Failure::TlsFailure);
                break;
            case WINHTTP_CALLBACK_STATUS_REQUEST_ERROR:
                end(value == ERROR_WINHTTP_TIMEOUT ? Failure::Timeout
                                                   : Failure::TransportUnavailable);
                break;
            default:
                break;
            }
        }
        void end(Failure failure) {
            if (phase == Phase::Closing || phase == Phase::Done)
                return;
            keep = shared_from_this();
            reply.failure = failure;
            deadline.stop();
            phase = Phase::Closing;
            if (failure != Failure::None)
                reply.body.clear();
            if (request) {
                auto h = request;
                request = nullptr;
                if (registered)
                    drain.start(5000);
                if (!WinHttpCloseHandle(h)) {
                    deliver();
                    QCoreApplication::exit(20);
                } else if (!registered) {
                    phase = Phase::Done;
                    deliver();
                    keep.reset();
                }
            } else {
                phase = Phase::Done;
                deliver();
                keep.reset();
            }
        }
        void deliver() {
            if (delivered)
                return;
            delivered = true;
            if (completion) {
                auto f = std::move(completion);
                f(std::move(reply));
            }
        }
    };
    class GetOperation final : public Operation {
        std::function<void()> cancel_;

      public:
        explicit GetOperation(std::function<void()> c) : cancel_(std::move(c)) {}
        ~GetOperation() override { cancel(); }
        void cancel() override {
            if (cancel_) {
                auto c = std::move(cancel_);
                c();
            }
        }
    };
    WinHttpGetTransport::WinHttpGetTransport(QObject *parent) : QObject(parent) {}
    WinHttpGetTransport::WinHttpGetTransport(const Activation &, QObject *parent) : QObject(parent) {}
    WinHttpGetTransport::~WinHttpGetTransport() {
        if (auto j = active_.lock())
            j->end(Failure::Cancelled);
    }
    std::unique_ptr<Operation> WinHttpGetTransport::start(Endpoint endpoint, Product product,
                                                          qint64 remaining, Completion completion) {
        if (QThread::currentThread() != thread())
            return {};
        auto j = std::make_shared<Job>();
        j->endpoint = endpoint;
        j->reply.endpoint = endpoint;
        j->completion = std::move(completion);
        auto op = std::make_unique<GetOperation>([weak = std::weak_ptr<Job>(j)] {
            if (auto s = weak.lock())
                QMetaObject::invokeMethod(
                    s.get(), [s] { s->end(Failure::Cancelled); }, Qt::QueuedConnection);
        });
        auto reject = [j](Failure f) { QTimer::singleShot(0, j.get(), [j, f] { j->end(f); }); };
        // Antes de crear WinHTTP o consultar tokens/perfil: no hay activacion por env/settings.
        if (!Activation::approved()) {
            reject(Failure::ConfigurationNotApproved);
            return op;
        }
        Broker::TokenIdentity id;
        if (!Broker::tokenIdentity(GetCurrentProcess(), id) || !id.ordinary) {
            reject(Failure::Unauthorized);
            return op;
        }
        auto spec = requestSpec(product, endpoint);
        if (!spec || remaining <= 0 || remaining > 12000 || !active_.expired()) {
            reject(Failure::TransportUnavailable);
            return op;
        }
        j->spec = *spec;
        active_ = j;
        j->arm(remaining);
        if (!j->prepare())
            j->end(Failure::TransportUnavailable);
        else
            j->send();
        return op;
    }
} // namespace Gate::Assistance::Retrieval
