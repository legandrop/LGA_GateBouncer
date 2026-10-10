#pragma once
#include "NativeSdk.h"
#include "../../../../common/token_ii_win.h"
#include <winioctl.h>
#include "../../../../common/classifier_protocol.h"
namespace gb::decisions { class NativeRuntime; }

namespace gatebouncer::service::windows::allapps::native {
class ClassifierCause;
// Owner exclusivo del dispositivo SYSTEM; ningún caller ordinary lo construye.
class NativeClassifier final : public std::enable_shared_from_this<NativeClassifier> {
    friend class gb::decisions::NativeRuntime;
    friend class NativeSource;
    friend class ClassifierCause;
    NativeClassifier() = default;
    static std::shared_ptr<NativeClassifier> open() noexcept;
    std::shared_ptr<ClassifierCause> take(bool &lost) noexcept;
    bool start() noexcept;
    bool reset() noexcept;
    bool decide(const GB_SCOPE_DECISION &, GB_SCOPE_RECEIPT &) noexcept;
    bool readback(const GB_SCOPE_DECISION &, GB_SCOPE_RECEIPT &) noexcept;
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
    UINT64 session_ = 0, loss_ = 0;
    mutable std::mutex mutex_;
};
class ClassifierCause final {
    friend class NativeClassifier;
    friend class NativeSource;
    friend class gb::decisions::NativeRuntime;
    ClassifierCause(std::shared_ptr<NativeClassifier>, GB_CLASSIFIER_RECORD,
                    gb::native::ProcessEvidence, gb::native::TokenEvidence);
    std::shared_ptr<NativeClassifier> owner_;
    GB_CLASSIFIER_RECORD record_{};
    gb::native::ProcessEvidence process_;
    gb::native::TokenEvidence token_;
public:
    ~ClassifierCause();
    bool current() const noexcept;
};
} // namespace gatebouncer::service::windows::allapps::native
