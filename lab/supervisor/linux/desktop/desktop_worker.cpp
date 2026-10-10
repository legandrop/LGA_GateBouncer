#include "PrivateDesktopOwner.hpp"
#include "../guestbroker/GuestBrokerBoundary.hpp"
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
        // El canal conserva el broker original y éste el HANDLE de ESTE child.
        // La adquisición SSH exige su productor de cuatro pins aún pendiente.
        while(acquired && admission->CurrentOwn() &&
            owner->InspectOwn().state==PrivateDesktopOwner::State::DesktopOwned) Sleep(100);
        while(owner->CloseOwn().state!=PrivateDesktopOwner::State::Closed) Sleep(50);
        while(!GuestBrokerBoundary::CloseHelperOwn(admission)) Sleep(50);
        return acquired?0:2;
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
