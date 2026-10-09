#include "PrivateDesktopOwner.hpp"
namespace gb {
class DesktopWorkerEntry final {
public:
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
int main(int argc, char**) {
    if (argc != 1) return 4;
    try { return gb::DesktopWorkerEntry::RunOwn(); } catch (...) { return 5; }
}
