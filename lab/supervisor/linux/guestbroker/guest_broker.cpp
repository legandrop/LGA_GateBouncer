#include "GuestBrokerBoundary.hpp"
int wmain(int argc,wchar_t**) {
    if(argc!=1) return 4;
    try { return gb::GuestBrokerBoundary::ServiceOwn(); }
    catch(...) { return 5; }
}
