#pragma once
#include "NativeSdk.h"
#include "../../../../common/token_ii_win.h"
#include <winioctl.h>
#include "../../../../common/classifier_protocol.h"
#include <condition_variable>
#include <thread>
#include <atomic>
namespace gb::decisions { class NativeRuntime; class NativeServer; }

namespace gatebouncer::service::windows::allapps::native {
class ClassifierCause;
class NativeImageWorker;
// Owner exclusivo del dispositivo SYSTEM; ningún caller ordinary lo construye.
class NativeClassifier final : public std::enable_shared_from_this<NativeClassifier> {
    friend class gb::decisions::NativeRuntime;
    friend class NativeSource;
    friend class ClassifierCause;
    friend class NativeImageWorker;
    NativeClassifier() = default;
    static std::shared_ptr<NativeClassifier> open() noexcept;
    std::shared_ptr<ClassifierCause> take(bool &lost) noexcept;
    bool start() noexcept;
    bool reset() noexcept;
    bool decide(const GB_SCOPE_DECISION &, GB_SCOPE_RECEIPT &) noexcept;
    bool readback(const GB_SCOPE_DECISION &, GB_SCOPE_RECEIPT &) noexcept;
    bool activity(const ClassifierCause &, const GB_SCOPE_DECISION &, HANDLE, GB_ACTIVITY_SNAPSHOT &) const noexcept;
    bool originalProcess(const ClassifierCause &) const noexcept;
    bool imageCurrent(const ClassifierCause &, HANDLE, GB_PROCESS_IMAGE_FACTS &) const noexcept;
    bool cancel(const GB_SCOPE_DECISION &, GB_CANCEL_RECEIPT &) noexcept;
    bool cancelReadback(const GB_SCOPE_DECISION &, GB_CANCEL_RECEIPT &) const noexcept;
    bool cancelIoctl(DWORD, const GB_SCOPE_DECISION &, GB_CANCEL_RECEIPT &) const noexcept;
    bool cancelledCurrent(const ClassifierCause &, const GB_SCOPE_DECISION &, HANDLE) const noexcept;
    bool scopeIoctl(DWORD, const GB_SCOPE_DECISION &, GB_SCOPE_RECEIPT &) noexcept;
    bool current(const ClassifierCause &) const noexcept;
    bool filterCurrent(const ClassifierCause &, HANDLE) const noexcept;
    bool catalogCurrent(const ClassifierCause &, HANDLE) const noexcept;
    void release(const GB_CLASSIFIER_QUERY &) noexcept;
    gb::native::Handle device_;
    std::shared_ptr<ClassifierCause> pendingApp_;
    UINT64 session_ = 0, loss_ = 0;
    mutable std::mutex mutex_;
};
class ClassifierCause final {
    friend class NativeClassifier;
    friend class NativeSource;
    friend class gb::decisions::NativeRuntime;
    friend class NativeImageWorker;
    ClassifierCause(std::shared_ptr<NativeClassifier>, GB_CLASSIFIER_RECORD,
                    gb::native::ProcessEvidence, gb::native::TokenEvidence);
    std::shared_ptr<NativeClassifier> owner_;
    GB_CLASSIFIER_RECORD record_{};
    gb::native::ProcessEvidence process_;
    gb::native::TokenEvidence token_;
    // Pending privado; únicamente el worker original puede admitir SameApp.
    std::atomic<unsigned> appState_{0}; // 0 pending, 1 matched, 2 rejected.
    std::uint64_t appJob_=0,appDeadline_=0; // Inmutables antes de publicar matched.
    bool appGap_=false; // Sólo el productor Runtime, dedup de cobertura del raw original.
public:
    ~ClassifierCause();
    bool current() const noexcept;
};
// Un solo préstamo físico; los resultados no poseen Runtime, actor ni Source.
class NativeImageWorker final {
    friend class gb::decisions::NativeRuntime;
    friend class gb::decisions::NativeServer;
    NativeImageWorker();
    struct Operation {
        gb::native::Handle device,event;
        OVERLAPPED overlap{};
        GB_CLASSIFIER_QUERY query{};
        GB_PROCESS_IMAGE_FACTS facts{};
    };
    struct Job { std::uint64_t id=0;std::shared_ptr<ClassifierCause> cause;std::shared_ptr<Operation> operation; };
    struct State {
        std::mutex mutex;
        std::condition_variable changed;
        gb::native::Handle wake;
        bool stop=false,eligible=false,completed=false,valid=false,finishing=false;
        std::size_t cancelBorrows=0;
        std::uint64_t sequence=0,id=0;
        GB_PROCESS_IMAGE_FACTS result{};
        std::unique_ptr<Job> queued;
        std::shared_ptr<Operation> physical;
        struct Retired { std::shared_ptr<void> owner;std::size_t charge=0;bool process=false; };
        std::array<Retired,64> retired{};
        std::size_t retiredCount=0,releasedCharge=0,releasedProcesses=0;
    };
    std::shared_ptr<State> state_;
    std::thread thread_;
    static void run(std::shared_ptr<State>) noexcept;
    std::uint64_t submit(const std::shared_ptr<ClassifierCause> &,std::uint64_t appDeadline=0) noexcept;
    bool result(std::uint64_t,GB_PROCESS_IMAGE_FACTS &,bool &) noexcept;
    void abandon(std::uint64_t) noexcept;
    void stop() noexcept;
    bool retire(std::shared_ptr<void> &,std::size_t,bool process=false) noexcept;
    std::size_t releasedCharge(std::size_t &) noexcept;
public:
    ~NativeImageWorker();
};
} // namespace gatebouncer::service::windows::allapps::native
