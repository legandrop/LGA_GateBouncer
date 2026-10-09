#pragma once
#include "LocalFacts.h"
#include <windows.h>
#include <vector>

namespace gatebouncer::localfacts::detail {
class Handle {
public:
    HANDLE value = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE h): value(h) {}
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept: value(other.value) { other.value = INVALID_HANDLE_VALUE; }
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
            value = other.value; other.value = INVALID_HANDLE_VALUE; }
        return *this;
    }
    explicit operator bool() const { return value && value != INVALID_HANDLE_VALUE; }
};
struct OpenFile { std::vector<Handle> ancestors; Handle file; Binding binding; };
State openLocal(const Request&, OpenFile&, DWORD&);
bool bindingFor(HANDLE, const std::wstring&, std::uint64_t, Binding&, DWORD&);
State hashFile(HANDLE, std::uint64_t, const Limits&, const Cancellation&, std::string&, DWORD&);
} // namespace gatebouncer::localfacts::detail
