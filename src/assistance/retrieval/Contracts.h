#pragma once
#include "../ExplanationContracts.h"
#include <array>
#include <map>
#include <vector>

namespace Gate::Assistance::Retrieval {
    enum class Product : quint32 {
        ObsStudio = 1001,
        NukeCandidate = 1002,
        UnknownSynthetic = 1999
    };
    enum class Provider : quint8 { Wikimedia = 1, GitHub = 2 };
    enum class Authority : quint8 { Community = 1, OfficialProjectMetadata = 2 };
    enum class State : quint8 {
        Idle,
        Searching,
        Explaining,
        SourcesRetrieved,
        Insufficient,
        Cancelled,
        ProviderUnavailable,
        Failed,
        CachedSources,
        PostUncertain
    };
    enum class Failure : quint16 {
        None,
        Malformed,
        Unsupported,
        Unauthorized,
        Stale,
        Capacity,
        VaultUnavailable,
        Corrupt,
        TransportUnavailable,
        TlsFailure,
        Timeout,
        Cancelled,
        RateLimited,
        InvalidResponse,
        Uncertain,
        ConfigurationNotApproved,
        VersionMismatch
    };
    enum class Endpoint : quint8 { WikiSearch, WikiSummary, GitHubRepo, GitHubLatest };
    enum class Model { Unselected, SyntheticFixture };
    struct Binding {
        RequestBinding request;
        quint64 retrievalEpoch = 0, catalogRevision = 0, providerPolicyEpoch = 0;
        quint16 disclosureVersion = 2;
        bool operator==(const Binding &other) const;
    };
    struct Source {
        quint8 id = 0;
        Provider provider = Provider::Wikimedia;
        Authority authority = Authority::Community;
        QString resource, title, url, excerpt;
        quint64 fetchedAt = 0, updatedAt = 0, revision = 0;
        QByteArray digest;
        // Original normalizado local; no se serializa por IPC ni sale al proveedor.
        QString normalizedContent;
        bool shortened = false;
    };
    struct Inference {
        ExplanationText text;
        std::vector<quint8> sourceIds;
    };
    struct Result {
        Binding binding;
        Product product = Product::UnknownSynthetic;
        State state = State::Insufficient;
        Failure failure = Failure::Uncertain;
        int observedHttpStatus = 0;
        std::vector<Source> sources;
        std::optional<Inference> inference;
    };
    struct HttpReply {
        Endpoint endpoint = Endpoint::WikiSearch;
        int status = 0;
        Failure failure = Failure::None;
        QByteArray body;
        quint32 retryAfter = 0;
    };
    class GetTransport {
      public:
        using Completion = std::function<void(HttpReply)>;
        virtual ~GetTransport() = default;
        virtual std::unique_ptr<Operation> start(Endpoint, Product, qint64 remainingMs,
                                                 Completion) = 0;
    };
    bool validBinding(const Binding &);
    bool safeText(const QString &, qsizetype maxBytes, bool allowEmpty = false);
    QString disclosure();
    QString identityDisclaimer();
    QString evidenceLicense();

    // GBAS2 conserva el encuadre, pero nunca decodifica una trama GBAS1 como retrieval.
    struct Frame {
        quint16 type = 12;
        std::array<unsigned char, 16> connection{}, correlation{};
        quint64 sequence = 0;
        std::map<quint16, QByteArray> fields;
    };
    void setBinding(Frame &, const Binding &);
    std::optional<Binding> frameBinding(const Frame &);
    std::optional<QByteArray> encodeFrame(const Frame &);
    std::optional<Frame> decodeFrame(const QByteArray &);
    std::optional<QByteArray> encodeSources(Product, const std::vector<Source> &);
    std::optional<std::vector<Source>> decodeSources(Product, const QByteArray &);
    class FrameReader {
      public:
        bool feed(const QByteArray &);
        std::optional<Frame> take();
        bool failed() const { return failed_; }

      private:
        QByteArray buffer_;
        bool failed_ = false;
    };
    // Puerta de respuestas para un cliente GBAS2: un trabajo activo, sin replay ni downgrade.
    class GroundedReplyGate final {
      public:
        explicit GroundedReplyGate(std::array<unsigned char, 16> connection);
        bool trackRequest(const Frame &);
        bool acceptReply(const Frame &);
        bool observeControl(quint16 type, const std::array<unsigned char, 16> &connection,
                            quint64 sequence);
        void cancel();
        bool failed() const { return failed_; }

      private:
        std::array<unsigned char, 16> connection_{};
        struct Tracked {
            Frame request;
            quint8 progress = 0;
            bool terminal = false;
        };
        std::optional<size_t> pending_;
        std::vector<Tracked> ledger_;
        quint64 expectedSequence_ = 1;
        bool failed_ = false;
        bool consumeSequence(const std::array<unsigned char, 16> &, quint64);
    };
} // namespace Gate::Assistance::Retrieval
