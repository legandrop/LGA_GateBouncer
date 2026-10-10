#include "PrivateDesktopOwner.hpp"
#include "../guestbroker/GuestBrokerBoundary.hpp"
#include "../OwnMemorySshCredential.hpp"
#include <cstring>
namespace gb {
class DesktopWorkerEntry final {
public:
    static int RunGuestOwn() {
        auto admission=GuestBrokerBoundary::AdmitHelperOwn();
        if(!admission || !admission->CurrentOwn()) return 6;
        PrivateDesktopOwner::DedicatedCreatorGuard entry;
        if(!admission->CurrentOwn()) return 6;
        auto owner=PrivateDesktopOwner::CreateOwn(entry);
        const bool acquired=owner->InspectOwn().state==PrivateDesktopOwner::State::DesktopOwned;
        std::shared_ptr<OwnMemorySshCredential> credential;
        if(acquired&&admission->CurrentOwn()) credential=OwnMemorySshCredential::CreateOwn(admission);
        const bool credentialAcquired=credential&&
            credential->InspectOwn().state==OwnMemorySshCredential::State::MemoryOwned;
        // El canal conserva el broker original y éste el HANDLE de ESTE child.
        // Sólo credencial/pipe propios: el productor Linux debe entregar su custodia antes de SSH.
        while(acquired && credential && admission->CurrentOwn() &&
            credential->InspectOwn().state==OwnMemorySshCredential::State::MemoryOwned &&
            owner->InspectOwn().state==PrivateDesktopOwner::State::DesktopOwned) Sleep(100);
        if(credential) while(credential->CloseOwn().state!=OwnMemorySshCredential::State::Closed) Sleep(50);
        while(owner->CloseOwn().state!=PrivateDesktopOwner::State::Closed) Sleep(50);
        while(!GuestBrokerBoundary::CloseHelperOwn(admission)) Sleep(50);
        return acquired&&credentialAcquired?0:2;
    }
    static int RunOwn() {
        PrivateDesktopOwner::DedicatedCreatorGuard entry;
        auto owner = PrivateDesktopOwner::CreateOwn(entry);
        const bool acquired = owner->InspectOwn().state == PrivateDesktopOwner::State::DesktopOwned;
        // Entry privado dedicado; sin Start/hijos, bombeo de GUI ni namespace publicado.
        while (owner->CloseOwn().state != PrivateDesktopOwner::State::Closed) Sleep(50);
        return acquired ? 0 : 2;
    }
};
}
int main(int argc, char** argv) {
    if(argc==2 && std::strcmp(argv[1],"--owned-guest")==0)
        try { return gb::DesktopWorkerEntry::RunGuestOwn(); } catch(...) { return 5; }
    if (argc != 1) return 4;
    try { return gb::DesktopWorkerEntry::RunOwn(); } catch (...) { return 5; }
}
