#pragma once
#include "wire_v1.h"
#include <filesystem>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace gb::native {
class Handle {
  public:
    HANDLE value = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { reset(); }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    Handle(Handle &&other) noexcept : value(other.value) { other.value = INVALID_HANDLE_VALUE; }
    Handle &operator=(Handle &&other) noexcept {
        if (this != &other) {
            reset();
            value = other.value;
            other.value = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    void reset(HANDLE h = INVALID_HANDLE_VALUE) {
        if (value && value != INVALID_HANDLE_VALUE)
            CloseHandle(value);
        value = h;
    }
    explicit operator bool() const { return value && value != INVALID_HANDLE_VALUE; }
};
bool protectedObject(HANDLE object, bool ancestor, bool directory, bool readableLeaf = false);
bool fixedPath(const std::filesystem::path &path);
bool protectedRegistry(HKEY key);
wire::Digest digest(const wire::Bytes &bytes);
wire::Id randomIdentity();
// Conserva handles de raíz a hoja; no repara permisos ni acepta rutas externas.
class ProtectedDirectory {
  public:
    explicit ProtectedDirectory(std::filesystem::path root, bool readableDeployment = false)
        : root_(std::move(root)), readable_(readableDeployment) {}
    bool acquire();
    bool writerLease(Handle &lease);
    bool read(const wchar_t *leaf, std::size_t cap, wire::Bytes &bytes, bool &exists);
    bool replace(const wchar_t *leaf, const wire::Bytes &bytes, bool stateSnapshot = false);
    const std::filesystem::path &root() const { return root_; }

  private:
    bool leafName(const wchar_t *leaf) const;
    std::filesystem::path root_;
    bool readable_ = false;
    std::vector<Handle> ancestors_;
};
} // namespace gb::native
