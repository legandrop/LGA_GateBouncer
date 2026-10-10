#include "FixedGuestBrokerSource.hpp"
#include "GuestBrokerBoundary.hpp"
#include "../helper/OwnedSuspendedProcess.hpp"
namespace gb {
std::recursive_mutex FixedGuestBrokerSource::mutex_;
std::shared_ptr<GuestNoJobObserver> FixedGuestBrokerSource::pending_;
bool FixedGuestBrokerSource::observing_ = false;
FixedGuestBrokerSource::Snapshot FixedGuestBrokerSource::InspectFixedOwn() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (observing_)
        return {Block::ObservationInProgress,
            {GuestNoJobObserver::State::Observing, GuestNoJobObserver::Cause::None, true}};
    if (pending_) {
        const auto closure = pending_->CloseOwn();
        if (closure.state != GuestNoJobObserver::State::Closed)
            return {Block::CreatorCleanupPending, closure};
        pending_.reset();
    }
    struct ObservingScope {
        bool& value;
        explicit ObservingScope(bool& active) : value(active) { value = true; }
        ~ObservingScope() { value = false; }
    } observing(observing_);
    auto observer = GuestNoJobObserver::ObserveCreatorOwn();
    pending_ = observer;
    const auto observation = observer->InspectOwn();
    const auto closure = observer->CloseOwn();
    if (closure.state != GuestNoJobObserver::State::Closed)
        return {Block::CreatorCleanupPending, observation};
    pending_.reset();
    if (observation.state != GuestNoJobObserver::State::Observed || observation.revoked)
        return {Block::CreatorObservationRejected, observation};
    // No hay owner VM, enrollment ni imagen retenida: ni Create ni Resume son admisibles.
    return {Block::VmOwnerEnrollmentImagePinMissing, observation};
}
std::shared_ptr<GuestNoJobObserver> FixedGuestBrokerSource::ObserveCreatedChildOwn(
    const std::shared_ptr<OwnedSuspendedProcess>& child) {
    return GuestNoJobObserver::ObserveChildOwn(child);
}
std::shared_ptr<GuestNoJobObserver> FixedGuestBrokerSource::ObserveOwnNative() {
    return GuestNoJobObserver::ObserveCreatorOwn();
}
bool FixedGuestBrokerSource::StartHelperOwn(const std::shared_ptr<BrokerAdmission>& admission,
    std::shared_ptr<OwnedSuspendedProcess>& child, std::shared_ptr<GuestNoJobObserver>& observation) {
    if(!admission || !admission->CurrentOwn() || child || observation) return false;
    auto guard=admission->noJob_->GuardOwn();
    const std::wstring image=L"C:\\GateBouncerLab\\bin\\desktop_worker.exe";
    std::wstring command=L"\""+image+L"\" --owned-guest";
    std::vector<wchar_t> argv(command.begin(),command.end()); argv.push_back(L'\0');
    std::wstring environment=L"SystemRoot=C:\\Windows"; environment.push_back(L'\0');
    environment+=L"WINDIR=C:\\Windows"; environment.push_back(L'\0'); environment.push_back(L'\0');
    if(!admission->CurrentOwn()) return false;
    // La factory existente reserva hoja/registro antes del SDK y captura ambos HANDLEs.
    const std::vector<wchar_t> environmentBlock(environment.begin(),environment.end());
    child=OwnedSuspendedProcess::CreateSuspendedOwn(image,std::move(argv),environmentBlock,L"C:\\GateBouncerLab\\bin");
    if(!child || child->InspectOwn().state!=OwnedSuspendedProcess::State::Suspended) return false;
    observation=ObserveCreatedChildOwn(child);
    if(!observation || observation->InspectOwn().state!=GuestNoJobObserver::State::Observed ||
       !admission->CurrentOwn()) return false;
    auto childGuard=observation->GuardOwn();
    std::lock_guard<std::recursive_mutex> operation(child->mutex_);
    if(!child->ReadIdentityOwn() || child->cancelRequested_.load() || child->revoked_ ||
        !admission->CurrentOwn() || observation->InspectOwn().state!=GuestNoJobObserver::State::Observed) return false;
    const DWORD previous=ResumeThread(child->thread_);
    if(previous!=1 || !admission->CurrentOwn()) {
        child->RevokeLocked(OwnedSuspendedProcess::Cause::ResumeUnconfirmed); return false;
    }
    child->state_=OwnedSuspendedProcess::State::Running; return true;
}
bool FixedGuestBrokerSource::ExactHelperOwn(const std::shared_ptr<OwnedSuspendedProcess>& child,
    HANDLE peer, DWORD pid, std::uint64_t created) {
    if(!child || !peer) return false;
    std::lock_guard<std::recursive_mutex> lock(child->mutex_);
    FILETIME actual{},exit{},kernel{},user{};
    return child->ReadIdentityOwn() && GetProcessId(peer)==pid && pid==child->pid_ &&
        created==child->creation_ && GetProcessTimes(peer,&actual,&exit,&kernel,&user) &&
        ((std::uint64_t(actual.dwHighDateTime)<<32)|actual.dwLowDateTime)==created &&
        WaitForSingleObject(peer,0)==WAIT_TIMEOUT;
}
}
