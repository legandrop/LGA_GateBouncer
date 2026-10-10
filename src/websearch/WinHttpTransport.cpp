#include "WebSearch.h"

#include <QCoreApplication>
#include <QUrlQuery>
#include <array>
#include <mutex>

#ifdef Q_OS_WIN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#endif

namespace gatebouncer::websearch {
namespace {
class ImmediateFailure final : public Exchange {
public:
    bool poll(HttpResponse &response) override { response = {}; return true; }
    void cancel() override {}
};
#ifdef Q_OS_WIN
enum class Phase { Waiting, Sent, Headers, Read, Done };
struct State {
    std::recursive_mutex mutex;
    HINTERNET session = nullptr;
    HINTERNET connection = nullptr;
    HINTERNET request = nullptr;
    Phase phase = Phase::Waiting;
    HttpResponse response;
    QByteArray body;
    std::array<char, 8192> buffer{};
    DWORD received = 0;
    ~State()
    {
        // El contexto del request conserva State hasta HANDLE_CLOSING.
        if (connection) WinHttpCloseHandle(connection);
        if (session) WinHttpCloseHandle(session);
    }
    void finish(bool success)
    {
        response.transportOk = success;
        phase = Phase::Done;
        const auto handle = request;
        request = nullptr;
        if (handle) WinHttpCloseHandle(handle);
    }
};
using Context = std::shared_ptr<State>;
void CALLBACK callback(HINTERNET, DWORD_PTR opaque, DWORD status, void *, DWORD size)
{
    if (!opaque) return;
    auto *context = reinterpret_cast<Context *>(opaque);
    if (status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) { delete context; return; }
    const auto state = *context;
    std::lock_guard<std::recursive_mutex> lock(state->mutex);
    if (state->phase == Phase::Done) return;
    switch (status) {
    case WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE: state->phase = Phase::Sent; break;
    case WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE: state->phase = Phase::Headers; break;
    case WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
        state->received = size;
        state->phase = Phase::Read;
        break;
    case WINHTTP_CALLBACK_STATUS_REQUEST_ERROR: state->finish(false); break;
    default: break;
    }
}
QByteArray header(HINTERNET request, DWORD name)
{
    std::array<wchar_t, 512> value{};
    DWORD bytes = DWORD(sizeof(value));
    if (!WinHttpQueryHeaders(request, name, WINHTTP_HEADER_NAME_BY_INDEX,
        value.data(), &bytes, WINHTTP_NO_HEADER_INDEX))
        return GetLastError() == ERROR_WINHTTP_HEADER_NOT_FOUND ? QByteArray{} : QByteArrayLiteral("invalid");
    return QString::fromWCharArray(value.data(), int(bytes / sizeof(wchar_t))).toLatin1();
}
class NativeExchange final : public Exchange {
public:
    explicit NativeExchange(Context state) : state_(std::move(state)) {}
    ~NativeExchange() override { cancel(); }
    void cancel() override
    {
        const auto state = state_;
        std::lock_guard<std::recursive_mutex> lock(state->mutex);
        if (state->phase != Phase::Done) state->finish(false);
    }
    bool poll(HttpResponse &response) override
    {
        const auto state = state_;
        std::lock_guard<std::recursive_mutex> lock(state->mutex);
        const auto handle = state->request;
        if (state->phase == Phase::Sent) {
            state->phase = Phase::Waiting;
            if (!WinHttpReceiveResponse(handle, nullptr)) state->finish(false);
        } else if (state->phase == Phase::Headers) {
            DWORD code = 0, size = sizeof(code);
            if (!WinHttpQueryHeaders(handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &code, &size, WINHTTP_NO_HEADER_INDEX)) state->finish(false);
            else {
                state->response.statusCode = int(code);
                state->response.contentType = header(handle, WINHTTP_QUERY_CONTENT_TYPE);
                state->response.contentEncoding = header(handle, WINHTTP_QUERY_CONTENT_ENCODING);
                if (code != 200) state->finish(true);
                else read(state);
            }
        } else if (state->phase == Phase::Read) {
            if (state->received > state->buffer.size()
                || state->response.body.size() + state->received > 256 * 1024) state->finish(false);
            else if (state->received == 0) state->finish(true);
            else {
                state->response.body.append(state->buffer.data(), state->received);
                read(state);
            }
        }
        if (state->phase != Phase::Done) return false;
        response = state->response;
        return true;
    }
private:
    static void read(const Context &state)
    {
        state->phase = Phase::Waiting;
        if (!WinHttpReadData(state->request, state->buffer.data(), DWORD(state->buffer.size()), nullptr))
            state->finish(false);
    }
    Context state_;
};
#endif
class NativeTransport final : public Transport {
public:
    std::shared_ptr<Exchange> start(const HttpRequest &input) override
    {
        if (!validConfiguration(input.config) || !validPublicQuery(input.query)||
            (input.resource!=Resource::Search&&!validResource(input.resource,input.evidenceUrl,input.destination))||
            (input.resource==Resource::Search&&(!input.evidenceUrl.isEmpty()||input.destination)))
            return std::make_shared<ImmediateFailure>();
        // La fábrica productiva funciona fuera de QA; el arnés nunca genera red real.
        if (qEnvironmentVariableIsSet("LGA_HEADLESS_DESKTOP")
            || qEnvironmentVariable("QT_QPA_PLATFORM") == QStringLiteral("offscreen")
            || qEnvironmentVariable("QT_QPA_PLATFORM") == QStringLiteral("minimal"))
            return std::make_shared<ImmediateFailure>();
#ifdef Q_OS_WIN
        const auto state = std::make_shared<State>();
        auto operation = std::make_shared<NativeExchange>(state);
        state->session = WinHttpOpen(L"GateBouncer Web Search", WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC);
        if (!state->session) return std::make_shared<ImmediateFailure>();
        if (!WinHttpSetTimeouts(state->session, 5000, 5000, 5000, 5000))
            return std::make_shared<ImmediateFailure>();
        const auto endpoint=input.resource==Resource::Search?input.config.endpoint:input.evidenceUrl;
        const auto host = endpoint.host().toStdWString();
        state->connection = WinHttpConnect(state->session, host.c_str(),
            INTERNET_PORT(endpoint.port(443)), 0);
        if (!state->connection) return std::make_shared<ImmediateFailure>();
        const bool post = input.resource==Resource::Search&&input.config.provider == Provider::SearXng;
        QString path = endpoint.path(QUrl::FullyEncoded);
        const auto encoded = QUrl::toPercentEncoding(input.query);
        if (post) state->body = "q=" + encoded + "&format=json&categories=general&pageno=1&language=en&safesearch=1";
        else if(input.resource==Resource::Search)path += QStringLiteral("?q=") + QString::fromLatin1(encoded);
        const auto widePath = path.toStdWString();
        state->request = WinHttpOpenRequest(state->connection, post ? L"POST" : L"GET",
            widePath.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!state->request) return std::make_shared<ImmediateFailure>();
        DWORD disable = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
        DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        DWORD autologon = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
        DWORD retries = 0;
        DWORD revocation = WINHTTP_ENABLE_SSL_REVOCATION;
        const auto req = state->request;
        if (!WinHttpSetOption(req, WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof(disable))
            || !WinHttpSetOption(req, WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect))
            || !WinHttpSetOption(req, WINHTTP_OPTION_AUTOLOGON_POLICY, &autologon, sizeof(autologon))
            || !WinHttpSetOption(req, WINHTTP_OPTION_ENABLE_FEATURE, &revocation, sizeof(revocation))
            || !WinHttpSetOption(req, WINHTTP_OPTION_CONNECT_RETRIES, &retries, sizeof(retries))) {
            state->finish(false);
            return operation;
        }
        auto *context = new Context(state);
        DWORD_PTR opaque = reinterpret_cast<DWORD_PTR>(context);
        // Registrar contexto antes del callback evita una liberación sin HANDLE_CLOSING.
        if (!WinHttpSetOption(req, WINHTTP_OPTION_CONTEXT_VALUE, &opaque, sizeof(opaque))) {
            delete context;
            state->finish(false);
            return operation;
        }
        if (WinHttpSetStatusCallback(req, callback, WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS
            | WINHTTP_CALLBACK_FLAG_HANDLES, 0) == WINHTTP_INVALID_STATUS_CALLBACK) {
            delete context;
            state->finish(false);
            return operation;
        }
        const wchar_t *headers = post
            ? L"Accept: application/json\r\nAccept-Encoding: identity\r\nContent-Type: application/x-www-form-urlencoded\r\n"
            : input.resource==Resource::AdobeEndpoints?L"Accept: text/html\r\nAccept-Encoding: identity\r\n"
            : input.resource==Resource::Search?L"Accept: application/json\r\nAccept-Encoding: identity\r\n"
            : L"Accept: application/rdap+json, application/json\r\nAccept-Encoding: identity\r\n";
        std::lock_guard<std::recursive_mutex> lock(state->mutex);
        if (!WinHttpSendRequest(req, headers, DWORD(-1), post ? state->body.data() : nullptr,
            DWORD(state->body.size()), DWORD(state->body.size()), opaque)) state->finish(false);
        return operation;
#else
        return std::make_shared<ImmediateFailure>();
#endif
    }
};
}
std::shared_ptr<Transport> makeWinHttpTransport() { return std::make_shared<NativeTransport>(); }
}
