#pragma once
#include "NativeRead.h"

namespace gatebouncer::service::windows::allapps::native {
// Firmas del SDK real. La sustitución sólo entra por el owner privado del source.
struct SdkApi {
    decltype(&guardedRead) read = &guardedRead;
    decltype(&copySdk) copy = &copySdk;
    decltype(&AllocateLocallyUniqueId) allocate = &AllocateLocallyUniqueId;
    decltype(&FwpmNetEventSubscribe2) subscribe = nullptr;
    decltype(&FwpmNetEventUnsubscribe0) unsubscribe = &FwpmNetEventUnsubscribe0;
    decltype(&FwpmEngineGetOption0) option = &FwpmEngineGetOption0;
    decltype(&FwpmFilterGetById0) filter = &FwpmFilterGetById0;
    decltype(&FwpmLayerGetById0) layer = &FwpmLayerGetById0;
    decltype(&FwpmFreeMemory0) freeMemory = &FwpmFreeMemory0;
    decltype(&FwpmTransactionBegin0) begin = &FwpmTransactionBegin0;
    decltype(&FwpmTransactionAbort0) abort = &FwpmTransactionAbort0;
    decltype(&FwpmFilterCreateEnumHandle0) createEnum = &FwpmFilterCreateEnumHandle0;
    decltype(&FwpmFilterEnum0) enumerate = &FwpmFilterEnum0;
    decltype(&FwpmFilterDestroyEnumHandle0) destroyEnum = &FwpmFilterDestroyEnumHandle0;
    std::shared_ptr<void> module;
};
SdkApi systemSdk();
} // namespace gatebouncer::service::windows::allapps::native
