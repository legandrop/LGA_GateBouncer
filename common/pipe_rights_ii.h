#pragma once
#include <cstdint>

namespace gb::ipc::ii {
// Delta de atributos independiente: sólo derechos de lectura añadidos al contrato II.
constexpr std::uint32_t ClientAccess = 0x00120083;
constexpr std::uint32_t OwnerRights = 0x00020000;
constexpr std::uint32_t ServerAccess = 0x001f01ff;
constexpr std::uint32_t CreateInstance = 0x00000004;
constexpr std::uint32_t ForbiddenClient =
    CreateInstance | 0x00000100 | 0x00000010 | 0x00010000 | 0x00040000 | 0x00080000 | 0xf0000000;
static_assert(ClientAccess == (0x1 | 0x2 | 0x80 | 0x20000 | 0x100000));
static_assert((ClientAccess & ForbiddenClient) == 0);
static_assert(OwnerRights == 0x20000);
static_assert((ServerAccess & CreateInstance) != 0);
// Son máscaras solicitadas/ACE; no predicen GrantedAccess ni prueban capacidad NPFS.
}
