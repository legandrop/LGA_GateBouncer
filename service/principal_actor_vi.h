#pragma once
#include "../common/token_ii_win.h"

namespace gb::decisions {
class NativeRuntime;
// Observador privado: sólo el owner conserva proceso, identidad y perfil.
// Los callbacks permiten QA del SDK sin abrir tokens ni procesos del host.
class PrincipalActorQuery {
    friend class NativeRuntime;
    struct Api {
        bool (*current)(const native::ProcessEvidence &) =
            [](const native::ProcessEvidence &actor) { return actor.current(); };
        decltype(&OpenProcessToken) open = &OpenProcessToken;
        bool (*read)(HANDLE, native::TokenEvidence &) = &native::tokenEvidence;
        decltype(&CloseHandle) close = &CloseHandle;
    };
    using Accept = bool (*)(void *, const native::TokenEvidence &) noexcept;
    static bool current(const native::ProcessEvidence &actor,
        const native::TokenEvidence &expected, const bool &cancelled,
        void *owner, Accept accept, const Api &api) noexcept {
        HANDLE token = nullptr;
        try {
            if (!api.current || !api.open || !api.read || !api.close || !accept ||
                !actor.process.value || cancelled || !api.current(actor) ||
                !accept(owner, expected) || cancelled) return false;
            if (!api.open(actor.process.value, TOKEN_QUERY, &token) || !token) {
                if (token) api.close(token);
                return false;
            }
            native::TokenEvidence fresh;
            const bool read = api.read(token, fresh);
            const bool closed = api.close(token) != FALSE;
            token = nullptr;
            return read && closed && fresh.account == expected.account &&
                fresh.logon == expected.logon && fresh.session == expected.session &&
                !cancelled && api.current(actor) && accept(owner, fresh) && !cancelled;
        } catch (...) {
            if (token && api.close) api.close(token);
            return false;
        }
    }
};
} // namespace gb::decisions
