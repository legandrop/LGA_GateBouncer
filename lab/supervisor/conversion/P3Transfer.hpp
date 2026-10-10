#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <array>
#include <cstdint>
namespace gb {
constexpr DWORD P3Flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY |
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_TIME;
constexpr SIZE_T P3Memory = 128u * 1024 * 1024;
constexpr LONGLONG P3Cpu = 100000000;
struct P3Descriptor final {
    std::uint32_t magic = 0x33504247, bytes = sizeof(P3Descriptor);
    std::array<std::uint64_t, 5> handles{};
    BY_HANDLE_FILE_INFORMATION input{};
    wchar_t run[37]{};
    std::uint32_t interfaceIndex = 0;
    std::int64_t start = 0, end = 0;
};
struct P3Result final {
    std::uint32_t magic = 0x52504247, bytes = sizeof(P3Result);
    std::uint32_t completed = 0, converted = 0, packets = 0, records = 0;
    std::uint32_t header = 0, eventsKnown = 0, eventsLost = 0, buffersKnown = 0, buffersLost = 0;
    std::uint32_t emittedKnown = 0;
    std::uint64_t reserved = 0, emitted = 0;
};
using P3Current = int (__cdecl*)();
bool P3LimitsCurrent(HANDLE job);
}
extern "C" {
#ifdef GB_P3_DLL
#define GB_P3_API __declspec(dllexport)
#else
#define GB_P3_API
#endif
GB_P3_API int __cdecl GbP3Convert(HANDLE input, const wchar_t* run, std::uint32_t interfaceIndex,
    std::int64_t start, std::int64_t end, const BYTE* workerPin, gb::P3Current current, gb::P3Result* result) noexcept;
GB_P3_API int __cdecl GbP3Drain(const wchar_t* run) noexcept;
}
