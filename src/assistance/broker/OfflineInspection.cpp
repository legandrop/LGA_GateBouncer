#include "OfflineInspection.h"
#include "BrokerPrimitives.h"
#include "../../../controller/deployment_win.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace Gate::Assistance::Broker {
namespace L = gatebouncer::localfacts;
namespace {
std::optional<std::chrono::milliseconds> milliseconds(const QString &text) {
    if (text.isEmpty() || text.size() > 5 || (text.size() > 1 && text.front() == '0')) return {};
    for (const auto ch : text) if (ch < '0' || ch > '9') return {};
    bool ok = false; const auto value = text.toUInt(&ok);
    return ok && value <= 30000 ? std::optional<std::chrono::milliseconds>(std::chrono::milliseconds(value)) : std::nullopt;
}
const char *stateName(L::State state) {
    switch (state) {
    case L::State::Complete: return "Complete";
    case L::State::Rejected: return "Rejected";
    case L::State::Unavailable: return "Unavailable";
    case L::State::Stale: return "Stale";
    case L::State::TooLarge: return "TooLarge";
    case L::State::TimedOut: return "TimedOut";
    case L::State::Cancelled: return "Cancelled";
    }
    return "Unavailable";
}
const char *signatureName(L::SignatureState state) {
    switch (state) {
    case L::SignatureState::VerifiedOffline: return "VerifiedOffline";
    case L::SignatureState::Unsigned: return "Unsigned";
    case L::SignatureState::Invalid: return "Invalid";
    case L::SignatureState::Unavailable: return "Unavailable";
    case L::SignatureState::TimedOut: return "TimedOut";
    case L::SignatureState::Cancelled: return "Cancelled";
    }
    return "Unavailable";
}
int output(const char *admission, const L::Snapshot &facts, int exitCode) {
    const bool complete = facts.state == L::State::Complete;
    const QJsonObject result{{"admission", admission}, {"state", stateName(facts.state)},
        {"signature", signatureName(facts.signature.state)}, {"nativeStatus", facts.signature.nativeStatus},
        {"bytes", complete ? QJsonValue(double(facts.binding.size)) : QJsonValue(QJsonValue::Null)},
        {"sha256", complete ? QString::fromStdString(facts.sha256) : QString{}},
        {"publisherAvailable", complete && facts.signature.state == L::SignatureState::VerifiedOffline && !facts.signature.publisherLocal.empty()},
        {"informationalOnly", true}};
    const auto bytes = QJsonDocument(result).toJson(QJsonDocument::Compact) + '\n';
    const auto stream = GetStdHandle(STD_OUTPUT_HANDLE); DWORD written = 0;
    if (!stream || stream == INVALID_HANDLE_VALUE || bytes.size() > 2048 ||
        !WriteFile(stream, bytes.constData(), DWORD(bytes.size()), &written, nullptr) || written != DWORD(bytes.size())) return 9;
    return exitCode;
}
bool sameLuid(const LUID &a, const LUID &b) { return a.HighPart == b.HighPart && a.LowPart == b.LowPart; }
bool statistics(HANDLE token, TOKEN_STATISTICS &value) {
    DWORD length = 0;
    return GetTokenInformation(token, TokenStatistics, &value, sizeof(value), &length) && length == sizeof(value);
}
struct OwnIdentity {
    Handle process, token;
    TokenIdentity identity;
    TOKEN_STATISTICS stamp{};
    quint64 creation = 0;
    bool acquire() {
        process.reset(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, GetCurrentProcessId()));
        HANDLE original = nullptr;
        if (!process || !processCreated(process.value, creation) || !OpenProcessToken(process.value, TOKEN_QUERY, &original)) return false;
        token.reset(original);
        return identityFromToken(token.value, identity) && identity.ordinary && statistics(token.value, stamp) && current();
    }
    bool current() const {
        quint64 now = 0; TokenIdentity identityNow; TOKEN_STATISTICS retained{}, fresh{}; HANDLE opened = nullptr;
        if (!process || !token || WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT ||
            GetProcessId(process.value) != GetCurrentProcessId() || !processCreated(process.value, now) || now != creation ||
            !statistics(token.value, retained) || !sameLuid(stamp.TokenId, retained.TokenId) ||
            !sameLuid(stamp.ModifiedId, retained.ModifiedId) || !OpenProcessToken(process.value, TOKEN_QUERY, &opened)) return false;
        Handle freshToken(opened);
        return identityFromToken(freshToken.value, identityNow) && identityNow.ordinary && sameIdentity(identity, identityNow) &&
            statistics(freshToken.value, fresh) && sameLuid(stamp.TokenId, fresh.TokenId) &&
            sameLuid(stamp.AuthenticationId, fresh.AuthenticationId) && sameLuid(stamp.ModifiedId, fresh.ModifiedId);
    }
};
class CancelMonitor final {
public:
    CancelMonitor(L::Cancellation &cancel, const std::optional<std::chrono::milliseconds> &after) {
        if (!after) return;
        if (after->count() == 0) { cancel.requested = true; return; }
        thread_ = std::thread([this,&cancel,delay=*after] {
            std::unique_lock<std::mutex> lock(mutex_);
            if (!condition_.wait_for(lock, delay, [this] { return done_; })) cancel.requested = true;
        });
    }
    ~CancelMonitor() {
        { std::lock_guard<std::mutex> lock(mutex_); done_ = true; }
        condition_.notify_all();
        if (thread_.joinable()) thread_.join();
    }
private:
    std::mutex mutex_;
    std::condition_variable condition_;
    bool done_ = false;
    std::thread thread_;
};
}
std::optional<OfflineInspectionOptions> offlineInspectionArguments(const QStringList &args) {
    if (args.size() < 3 || args.size() > 9 || args[1] != "--inspect-offline" ||
        args[2].isEmpty() || args[2].size() > 240 || args[2].contains(QChar::Null) || args.size() % 2 == 0) return {};
    OfflineInspectionOptions options; options.request.absolutePath = args[2].toStdWString(); options.request.generation = 1;
    bool hash = false, signature = false, cancel = false;
    for (qsizetype i = 3; i < args.size(); i += 2) {
        const auto value = milliseconds(args[i+1]); if (!value) return {};
        if (args[i] == "--hash-ms" && !hash) { hash = true; options.limits.hashBudget = *value; }
        else if (args[i] == "--signature-ms" && !signature) { signature = true; options.limits.signatureBudget = *value; }
        else if (args[i] == "--cancel-after-ms" && !cancel) { cancel = true; options.cancelAfter = *value; }
        else return {};
    }
    return options;
}
int runOfflineInspection(const QStringList &args) {
    const auto options = offlineInspectionArguments(args);
    if (!options) return output("InvalidArguments", {}, 2);
    try {
        OwnIdentity own;
        if (!own.acquire()) return output("OrdinaryIdentityUnavailable", {}, 3);
        const auto image = std::filesystem::path(imagePath(own.process.value).toStdWString());
        auto deployment = std::make_shared<gb::controller::Deployment>(image.parent_path());
        if (!deployment->verify(image, gb::controller::DeploymentRole::AssistantBroker) ||
            !deployment->current() || !own.current()) return output("DeploymentUnavailable", {}, 4);
        // El constructor recibe sólo el inventario original retenido, no ruta/hash externos.
        L::WindowsSignatureBackend backend(deployment); L::Cancellation cancellation;
        L::Snapshot facts;
        {
            CancelMonitor monitor(cancellation, options->cancelAfter);
            facts = L::inspect(options->request, options->limits, cancellation, backend);
        }
        if (cancellation.requested.load()) { facts = {}; facts.state = L::State::Cancelled; }
        if (!own.current() || !deployment->current()) {
            facts = {}; facts.state = L::State::Stale;
            return output("Changed", facts, 7);
        }
        const int exitCode = facts.state == L::State::Cancelled ? 5 :
            facts.state == L::State::TimedOut || facts.signature.state == L::SignatureState::TimedOut ? 6 :
            facts.state == L::State::Complete ? 0 : 8;
        return output("Current", facts, exitCode);
    } catch (...) { return output("InspectionUnavailable", {}, 8); }
}
}
