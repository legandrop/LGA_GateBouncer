#pragma once
#include <cwchar>

namespace gb::controller {
// Sólo opciones propias, antes de cualquier loader o constructor Qt.
inline bool ordinaryArguments(int argc, const wchar_t *const *argv) noexcept {
    return (argc == 1 || argc == 2) && argv && argv[0] && *argv[0] &&
        (argc == 1 || (argv[1] && std::wcscmp(argv[1], L"--start-minimized") == 0));
}
} // namespace gb::controller
