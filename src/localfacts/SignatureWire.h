#pragma once
#include <cstdint>
#include <type_traits>
namespace gatebouncer::localfacts::detail {
// Respuesta de tamaño fijo; no hay datos de entrada ni rutas externas en el mapping.
struct SignatureWire {
    std::uint32_t magic = 0;
    std::uint32_t state = 3;
    std::int32_t nativeStatus = 0;
    std::uint32_t publisherLength = 0;
    wchar_t publisher[256]{};
};
inline constexpr std::uint32_t wireMagic = 0x47425331;
static_assert(std::is_trivially_copyable_v<SignatureWire>);
}
