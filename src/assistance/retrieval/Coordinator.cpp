#include "Coordinator.h"
#include "../broker/BrokerPrimitives.h"
#include "Catalog.h"
#include "GroundedParser.h"
#include "GroundedPayload.h"
#include "ProviderPolicy.h"
#include "SourceNormalizer.h"
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QPointer>
#include <QUuid>
#include <algorithm>
#include <chrono>
#include <limits>
#include <sddl.h>
namespace Gate::Assistance::Retrieval {
    struct BudgetGuard::Impl {
        QString root;
        Broker::TokenIdentity identity;
        std::vector<Broker::Handle> parents;
        Broker::Handle lock;
        void *descriptor = nullptr;
        bool prepared = false;
        quint64 lastSeen = 0;
        quint64 wikiBlocked = 0, githubBlocked = 0;
        ~Impl() {
            if (descriptor)
                LocalFree(descriptor);
        }
    };
    BudgetGuard::BudgetGuard() : impl_(std::make_unique<Impl>()) {}
    BudgetGuard::BudgetGuard(const Activation &) : BudgetGuard() {}
    BudgetGuard::BudgetGuard(QString root) : BudgetGuard() { impl_->root = std::move(root); }
    BudgetGuard::~BudgetGuard() = default;
    static Broker::Handle checked(const QString &path, bool dir, const Broker::TokenIdentity &id,
                                  bool own) {
        Broker::Handle h(CreateFileW(
            path.toStdWString().c_str(), GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | (dir ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr));
        BY_HANDLE_FILE_INFORMATION info{};
        if (!h || !GetFileInformationByHandle(h.value, &info) ||
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
            bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != dir ||
            (!dir && info.nNumberOfLinks != 1) || (own && !Broker::exactFileSecurity(h.value, id)))
            return {};
        return h;
    }
    static void put(QByteArray &b, quint64 n) {
        for (int i = 0; i < 8; ++i)
            b += char(n >> (8 * i));
    }
    static quint64 read(const QByteArray &b, int p) {
        quint64 n = 0;
        for (int i = 0; i < 8; ++i)
            n |= quint64(static_cast<unsigned char>(b[p + i])) << (8 * i);
        return n;
    }
    Failure BudgetGuard::reserve(quint64 now) {
        auto &i = *impl_;
        if (i.root.isEmpty() || !now || now < i.lastSeen)
            return Failure::ConfigurationNotApproved;
        if (!i.prepared) {
            i.parents.clear();
            i.lock.reset();
            if (i.descriptor) {
                LocalFree(i.descriptor);
                i.descriptor = nullptr;
            }
            const QString root = QDir::fromNativeSeparators(i.root);
            const auto parts = root.split('/');
            if (parts.size() < 3 || parts[0].size() != 2 || parts[0][1] != ':' ||
                parts.contains(".") || parts.contains("..") || parts.contains("") ||
                GetDriveTypeW((parts[0] + "/").toStdWString().c_str()) != DRIVE_FIXED ||
                !Broker::tokenIdentity(GetCurrentProcess(), i.identity) || !i.identity.ordinary)
                return Failure::VaultUnavailable;
            LPWSTR sid = nullptr;
            if (!ConvertSidToStringSidW(i.identity.user.data(), &sid))
                return Failure::VaultUnavailable;
            const std::wstring sddl =
                L"O:" + std::wstring(sid) + L"D:P(A;;FA;;;" + std::wstring(sid) + L")(A;;FA;;;SY)";
            LocalFree(sid);
            PSECURITY_DESCRIPTOR sd = nullptr;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                                                                      &sd, nullptr))
                return Failure::VaultUnavailable;
            i.descriptor = sd;
            QString p = parts[0] + "/";
            for (int k = 0; k < parts.size(); ++k) {
                if (k)
                    p += (k == 1 ? "" : "/") + parts[k];
                auto h = checked(p, true, i.identity, k == parts.size() - 1);
                if (!h)
                    return Failure::VaultUnavailable;
                i.parents.push_back(std::move(h));
            }
            i.root = QDir::toNativeSeparators(root);
            SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
            i.lock.reset(CreateFileW((i.root + "\\retrieval-owner.lock").toStdWString().c_str(),
                                     GENERIC_READ | READ_CONTROL, 0, &sa, OPEN_ALWAYS,
                                     FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            BY_HANDLE_FILE_INFORMATION info{};
            if (!i.lock || !Broker::exactFileSecurity(i.lock.value, i.identity) ||
                !GetFileInformationByHandle(i.lock.value, &info) ||
                (info.dwFileAttributes &
                 (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
                info.nNumberOfLinks != 1)
                return Failure::VaultUnavailable;
            i.prepared = true;
        }
        if (!Broker::exactFileSecurity(i.parents.back().value, i.identity))
            return Failure::VaultUnavailable;
        const QString path = i.root + "\\retrieval-usage.v1";
        DWORD attr = GetFileAttributesW(path.toStdWString().c_str());
        quint64 day = now / 86400000, hour = now / 3600000, last = 0, days = 0, hours = 0;
        bool exists = attr != INVALID_FILE_ATTRIBUTES;
        if (exists) {
            auto file = checked(path, false, i.identity, true);
            LARGE_INTEGER size{};
            QByteArray record(80, '\0');
            DWORD got = 0;
            if (!file || !GetFileSizeEx(file.value, &size) || size.QuadPart != 80 ||
                !ReadFile(file.value, record.data(), 80, &got, nullptr) || got != 80 ||
                record.left(8) != "GBRU0001" ||
                record.mid(48, 32) !=
                    QCryptographicHash::hash(record.left(48), QCryptographicHash::Sha256))
                return Failure::Corrupt;
            const auto oldDay = read(record, 8), oldHour = read(record, 16);
            days = read(record, 24);
            hours = read(record, 32);
            last = read(record, 40);
            if (days > 24 || hours > 12 || oldDay != last / 86400000 || oldHour != last / 3600000 ||
                now < last)
                return Failure::Corrupt;
            if (oldDay != day)
                days = 0;
            if (oldHour != hour)
                hours = 0;
        } else if (GetLastError() != ERROR_FILE_NOT_FOUND)
            return Failure::VaultUnavailable;
        if (days >= 24 || hours >= 12)
            return Failure::RateLimited;
        QByteArray record("GBRU0001", 8);
        for (auto n : {day, hour, days + 1, hours + 1, now})
            put(record, n);
        record += QCryptographicHash::hash(record, QCryptographicHash::Sha256);
        const QString temp =
            i.root + "\\retrieval-pending-" + QUuid::createUuid().toString(QUuid::Id128) + ".tmp";
        SECURITY_ATTRIBUTES sa{sizeof(sa), i.descriptor, FALSE};
        Broker::Handle file(CreateFileW(temp.toStdWString().c_str(), GENERIC_WRITE | READ_CONTROL,
                                        0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        DWORD written = 0;
        if (!file || !Broker::exactFileSecurity(file.value, i.identity) ||
            !WriteFile(file.value, record.data(), DWORD(record.size()), &written, nullptr) ||
            written != record.size() || !FlushFileBuffers(file.value))
            return Failure::VaultUnavailable;
        file.reset();
        if (!(exists ? ReplaceFileW(path.toStdWString().c_str(), temp.toStdWString().c_str(),
                                    nullptr, 0, nullptr, nullptr)
                     : MoveFileExW(temp.toStdWString().c_str(), path.toStdWString().c_str(),
                                   MOVEFILE_WRITE_THROUGH)))
            return Failure::VaultUnavailable;
        auto stored = checked(path, false, i.identity, true);
        LARGE_INTEGER size{};
        QByteArray actual(80, '\0');
        DWORD got = 0;
        if (!stored || !GetFileSizeEx(stored.value, &size) || size.QuadPart != 80 ||
            !ReadFile(stored.value, actual.data(), 80, &got, nullptr) || got != 80 ||
            actual != record)
            return Failure::VaultUnavailable;
        i.lastSeen = now;
        return Failure::None;
    }
    void BudgetGuard::cooldown(Provider p, quint64 now, quint32 seconds) {
        const auto until =
            seconds > 3600 || now > std::numeric_limits<quint64>::max() - quint64(seconds) * 1000
                ? std::numeric_limits<quint64>::max()
                : now + quint64(seconds) * 1000;
        auto &value = p == Provider::Wikimedia ? impl_->wikiBlocked : impl_->githubBlocked;
        value = qMax(value, until);
    }
    bool BudgetGuard::providerReady(Provider p, quint64 now) const {
        return now >= impl_->lastSeen &&
               now >= (p == Provider::Wikimedia ? impl_->wikiBlocked : impl_->githubBlocked);
    }
    Coordinator::Coordinator(GetTransport &g, IExplanationTransport &m, BudgetGuard &b,
                             QObject *parent)
        : QObject(parent), get_(g), model_(m), budget_(b) {
        monotonic_ = [] {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                .count();
        };
        utc_ = [] { return QDateTime::currentMSecsSinceEpoch(); };
        deadline_.setSingleShot(true);
        connect(&deadline_, &QTimer::timeout, this,
                [this] { finish(State::Failed, Failure::Timeout); });
    }
    Coordinator::~Coordinator() {
        active_ = false;
        ++invalidating_;
        nvidiaConsent_ = webConsent_ = false;
        completion_ = {};
        progress_ = {};
        ++serial_;
        deadline_.stop();
        if (operation_)
            operation_->cancel();
    }
    Coordinator::Coordinator(GetTransport &g, IExplanationTransport &m, BudgetGuard &b,
                             const PayloadBuilder &builder, QObject *parent)
        : Coordinator(g, m, b, parent) {
        builder_ = &builder;
    }
    void Coordinator::configure(bool n, bool w, quint64 epoch, bool automatic) {
        const bool changed = n != nvidiaConsent_ || w != webConsent_ || epoch != consentEpoch_;
        nvidiaConsent_ = n;
        webConsent_ = w;
        consentEpoch_ = epoch;
        automatic_ = automatic;
        if (changed) {
            ++invalidating_;
            cache_.clear();
            sources_.clear();
            QPointer<Coordinator> self(this);
            cancel();
            if (self)
                --invalidating_;
        }
    }
    void Coordinator::setContext(const Binding &b, Product p) {
        if (!(b == context_) || p != product_) {
            context_ = b;
            product_ = p;
            ++invalidating_;
            cache_.clear();
            sources_.clear();
            QPointer<Coordinator> self(this);
            cancel();
            if (self)
                --invalidating_;
        }
    }
    bool Coordinator::eligible() const {
        return !invalidating_ && (synthetic_ || Activation::approved()) && nvidiaConsent_ &&
               webConsent_ && context_.retrievalEpoch == consentEpoch_ && validBinding(context_) &&
               eligibleProduct(product_);
    }
    bool Coordinator::current(quint64 s) const {
        return active_ && s == serial_ && eligible() && submitted_ == context_ &&
               submittedProduct_ == product_ && monotonic_() >= started_ && utc_() >= startedUtc_ &&
               utc_() >= lastUtc_;
    }
    bool Coordinator::consumed() const {
        for (const auto &c : consumed_)
            if (c.requestId == context_.request.context.requestId &&
                c.applicationIdentity == context_.request.context.applicationIdentity &&
                c.snapshotRevision == context_.request.context.snapshotRevision &&
                c.sessionEpoch == context_.request.context.sessionEpoch)
                return true;
        return false;
    }
    bool Coordinator::start(Completion completion, Progress progress) {
        if (active_ || !eligible())
            return false;
        const auto now = monotonic_();
        const auto wall = utc_();
        if (wall <= 0 || wall < lastUtc_ || wall > 253402300799999LL) {
            cache_.clear();
            return false;
        }
        lastUtc_ = wall;
        for (const auto &cache : cache_)
            if (cache.binding == context_ && cache.product == product_ && now >= cache.saved &&
                now - cache.saved <= 300000) {
                state_ = State::CachedSources;
                Result r{context_, product_,      state_,         Failure::None,
                         200,      cache.sources, cache.inference};
                if (completion)
                    completion(std::move(r));
                return true;
            }
        if (consumed() || consumed_.size() >= 60)
            return false;
        if (budget_.reserve(quint64(wall)) != Failure::None)
            return false;
        consumed_.push_back(context_.request.context);
        submitted_ = context_;
        submittedProduct_ = product_;
        completion_ = std::move(completion);
        progress_ = std::move(progress);
        sources_.clear();
        received_ = 0;
        page_ = 0;
        stage_ = 0;
        repositoryAccepted_ = false;
        started_ = now;
        startedUtc_ = wall;
        active_ = true;
        ++serial_;
        deadline_.start(32000);
        state_ = State::Searching;
        const auto enteredSerial = serial_;
        const auto enteredBinding = submitted_;
        const auto enteredProduct = submittedProduct_;
        auto progressCallback = progress_;
        QPointer<Coordinator> self(this);
        if (progressCallback)
            progressCallback(State::Searching);
        if (self && current(enteredSerial) && state_ == State::Searching &&
            submitted_ == enteredBinding && submittedProduct_ == enteredProduct)
            next();
        return true;
    }
    void Coordinator::cancel() {
        if (active_)
            finish(State::Cancelled, Failure::Cancelled);
        else {
            ++serial_;
            auto operation = std::move(operation_);
            if (operation)
                operation->cancel();
        }
    }
    void Coordinator::providerWithdrawn() {
        webConsent_ = false;
        ++invalidating_;
        cache_.clear();
        sources_.clear();
        QPointer<Coordinator> self(this);
        cancel();
        if (self)
            --invalidating_;
    }
    void Coordinator::next() {
        if (!current(serial_)) {
            cancel();
            return;
        }
        lastUtc_ = utc_();
        const auto elapsed = monotonic_() - started_;
        if (elapsed >= 12000) {
            finish(State::ProviderUnavailable, Failure::Timeout);
            return;
        }
        if (stage_ >= 4) {
            if (sources_.empty()) {
                finish(State::Insufficient, Failure::Uncertain);
                return;
            }
            explain();
            return;
        }
        const auto endpoint = Endpoint(stage_);
        if ((endpoint == Endpoint::WikiSummary && !page_) ||
            (endpoint == Endpoint::GitHubLatest && !repositoryAccepted_)) {
            ++stage_;
            next();
            return;
        }
        const auto provider = stage_ < 2 ? Provider::Wikimedia : Provider::GitHub;
        if (!budget_.providerReady(provider, quint64(utc_()))) {
            finish(State::ProviderUnavailable, Failure::RateLimited);
            return;
        }
        ++serial_;
        const auto submittedSerial = serial_;
        const auto submittedProduct = submittedProduct_;
        QPointer<Coordinator> self(this);
        operation_.reset();
        if (!self || !current(submittedSerial) || state_ != State::Searching)
            return;
        auto op = get_.start(endpoint, submittedProduct, 12000 - elapsed,
                             [self, submittedSerial](HttpReply r) {
                                 if (self)
                                     QMetaObject::invokeMethod(
                                         self,
                                         [self, submittedSerial, r = std::move(r)]() mutable {
                                             if (self)
                                                 self->got(submittedSerial, std::move(r));
                                         },
                                         Qt::QueuedConnection);
                             });
        if (!self) {
            if (op)
                op->cancel();
            return;
        }
        if (current(submittedSerial))
            operation_ = std::move(op);
        else if (op)
            op->cancel();
        if (self && current(submittedSerial) && !operation_)
            finish(State::ProviderUnavailable, Failure::TransportUnavailable);
    }
    void Coordinator::got(quint64 s, HttpReply reply) {
        if (!current(s)) {
            if (active_ && s == serial_)
                cancel();
            return;
        }
        lastUtc_ = utc_();
        if (monotonic_() - started_ >= 12000) {
            finish(State::ProviderUnavailable, Failure::Timeout);
            return;
        }
        if (reply.endpoint != Endpoint(stage_) || reply.body.size() > 131072 ||
            received_ + reply.body.size() > 524288) {
            finish(State::Failed, Failure::InvalidResponse);
            return;
        }
        received_ += reply.body.size();
        if (reply.status == 429 || reply.status == 503) {
            budget_.cooldown(stage_ < 2 ? Provider::Wikimedia : Provider::GitHub, quint64(utc_()),
                             reply.retryAfter ? reply.retryAfter : 60);
            finish(State::ProviderUnavailable, Failure::RateLimited, reply.status);
            return;
        }
        if (reply.failure != Failure::None || reply.status != 200) {
            if (reply.status == 404) {
                ++stage_;
                next();
                return;
            }
            finish(State::ProviderUnavailable,
                   reply.failure == Failure::None ? Failure::TransportUnavailable : reply.failure,
                   reply.status);
            return;
        }
        if (stage_ == 0)
            page_ = searchPage(product_, reply.body).value_or(0);
        else {
            auto source =
                normalizeSource(product_, reply.endpoint, reply.body, quint64(utc_()), page_);
            if (stage_ == 2)
                repositoryAccepted_ = source.has_value();
            if (stage_ == 2 && !repositoryAccepted_) {
                finish(State::Insufficient, Failure::Uncertain);
                return;
            }
            if (source)
                sources_.push_back(std::move(*source));
        }
        ++stage_;
        next();
    }
    void Coordinator::explain() {
        if (!current(serial_)) {
            cancel();
            return;
        }
        lastUtc_ = utc_();
        if (sources_.empty()) {
            finish(State::Insufficient, Failure::Uncertain);
            return;
        }
        std::stable_sort(sources_.begin(), sources_.end(), [](const Source &a, const Source &b) {
            return int(a.authority) > int(b.authority);
        });
        const auto enteredSerial = serial_;
        const auto enteredBinding = submitted_;
        const auto enteredProduct = submittedProduct_;
        const auto enteredState = state_;
        const auto stableSources = sources_;
        QPointer<Coordinator> self(this);
        auto body = builder_ ? builder_->build(enteredProduct, stableSources)
                             : groundedPayload(enteredProduct, stableSources,
                                               synthetic_ ? Model::SyntheticFixture
                                                          : Model::Unselected);
        if (!self || !current(enteredSerial) || state_ != enteredState ||
            !(submitted_ == enteredBinding) || submittedProduct_ != enteredProduct)
            return;
        if (monotonic_() - started_ >= 32000) {
            finish(State::Failed, Failure::Timeout);
            return;
        }
        if (!body || body->size() > 4096) {
            finish(State::Failed, Failure::ConfigurationNotApproved);
            return;
        }
        state_ = State::Explaining;
        auto progressCallback = progress_;
        if (progressCallback)
            progressCallback(State::Explaining);
        if (!self || !current(enteredSerial) || state_ != State::Explaining ||
            !(submitted_ == enteredBinding) || submittedProduct_ != enteredProduct)
            return;
        ++serial_;
        const auto submittedSerial = serial_;
        operation_.reset();
        if (!self || !current(submittedSerial) || state_ != State::Explaining)
            return;
        const auto remaining = qint64(32000) - (monotonic_() - started_);
        if (remaining <= 0) {
            finish(State::Failed, Failure::Timeout);
            return;
        }
        deadline_.start(int(qMin(qint64(20000), remaining)));
        auto op =
            model_.start(enteredBinding.request, *body, [self, submittedSerial](TransportReply r) {
                if (self)
                    QMetaObject::invokeMethod(
                        self,
                        [self, submittedSerial, r = std::move(r)]() mutable {
                            if (self)
                                self->explained(submittedSerial, std::move(r));
                        },
                        Qt::QueuedConnection);
            });
        if (!self) {
            if (op)
                op->cancel();
            return;
        }
        if (current(submittedSerial))
            operation_ = std::move(op);
        else if (op)
            op->cancel();
        if (self && current(submittedSerial) && !operation_)
            finish(State::Failed, Failure::TransportUnavailable);
    }
    void Coordinator::explained(quint64 s, TransportReply reply) {
        if (!current(s)) {
            if (active_ && s == serial_)
                cancel();
            return;
        }
        lastUtc_ = utc_();
        if (!(reply.binding == submitted_.request)) {
            finish(State::Cancelled, Failure::Cancelled);
            return;
        }
        if (monotonic_() - started_ >= 32000) {
            finish(State::Failed, Failure::Timeout);
            return;
        }
        if (reply.statusCode != 200 || reply.error != Error::None) {
            finish(State::Failed,
                   reply.error == Error::Timeout ? Failure::Timeout : Failure::TransportUnavailable,
                   reply.statusCode);
            return;
        }
        auto i = parseGroundedEnvelope(reply.body, sources_);
        if (!i) {
            finish(State::Failed, Failure::InvalidResponse, reply.statusCode);
            return;
        }
        finish(State::SourcesRetrieved, Failure::None, 200, std::move(i));
    }
    void Coordinator::finish(State state, Failure failure, int http, std::optional<Inference> i) {
        if (!active_)
            return;
        active_ = false;
        ++serial_;
        deadline_.stop();
        state_ = state;
        auto operation = std::move(operation_);
        auto callback = std::move(completion_);
        progress_ = {};
        if (state == State::SourcesRetrieved && i) {
            cache_.push_back({submitted_, submittedProduct_, sources_, *i, monotonic_()});
            if (cache_.size() > 16)
                cache_.pop_front();
        }
        Result r{submitted_, submittedProduct_, state, failure, http, sources_, std::move(i)};
        sources_.clear();
        if (operation)
            operation->cancel();
        if (callback)
            callback(std::move(r));
    }
} // namespace Gate::Assistance::Retrieval
