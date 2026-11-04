// Pruebas del motor que no tocan WFP ni la red: se pueden correr sin administrador y con el servicio instalado.
// Salida: una línea por caso y código 0 si pasan todos.
#include "destination_match.h"
#include "name_wait.h"
#include <cstdio>
#include <map>
#include <string>

namespace {

int failures = 0;

void check(const wchar_t *name, bool ok) {
    std::wprintf(L"%ls  %ls\n", ok ? L"PASS" : L"FAIL", name);
    if (!ok) ++failures;
}

using Clock = gbe::NameWait<int>::Clock;
using std::chrono::milliseconds;

// Un bloqueo de una app en modo por destino, como lo ve el motor.
struct Drop {
    std::wstring address;
};

// Lo que el motor hace con un bloqueo cuando ya tiene (o no) el nombre: «allow» si la regla lo cubre, «ask» si no.
std::wstring verdict(const std::wstring &rule, const std::map<std::wstring, std::wstring> &names, const Drop &d) {
    const auto n = names.find(d.address);
    return gbe::destinationMatch(rule, n == names.end() ? std::wstring() : n->second, d.address) ? L"allow" : L"ask";
}

void destinationMatchNeedsTheName() {
    // La causa del pedido falso: con la regla ya guardada, el bloqueo llega sin nombre y no coincide.
    check(L"regla *.dominio sin nombre todavía: no coincide",
          gbe::destinationMatch(L"*.googleusercontent.com", L"", L"142.251.129.129") == 0);
    check(L"regla *.dominio con el nombre: coincide",
          gbe::destinationMatch(L"*.googleusercontent.com", L"doc-04-34-sheets.googleusercontent.com",
                                L"142.251.129.129") > 0);
    check(L"regla por IP: coincide sin nombre",
          gbe::destinationMatch(L"142.251.129.129", L"", L"142.251.129.129") > 0);
    check(L"regla *.dominio no cubre otro dominio",
          gbe::destinationMatch(L"*.googleusercontent.com", L"docs.google.com", L"142.251.129.129") == 0);
}

void nameWaitReleasesWhenTheNameArrives() {
    gbe::NameWait<Drop> wait(std::chrono::seconds(2), 10);
    const auto t0 = Clock::now();
    std::map<std::wstring, std::wstring> names;
    const auto named = [&](const Drop &d) { return names.count(d.address) > 0; };
    check(L"retiene el bloqueo sin nombre", wait.hold({L"142.251.129.129"}, t0));
    check(L"antes del nombre y de la espera no suelta nada", wait.release(t0 + milliseconds(300), named).empty());
    // El DNS de Windows llega ~1 s después del intento.
    names[L"142.251.129.129"] = L"doc-04-34-sheets.googleusercontent.com";
    const auto out = wait.release(t0 + milliseconds(900), named);
    check(L"al llegar el nombre lo suelta sin esperar el vencimiento", out.size() == 1);
    check(L"y con el nombre la regla lo resuelve: no se pregunta",
          out.size() == 1 && verdict(L"*.googleusercontent.com", names, out[0]) == L"allow");
    check(L"queda vacía", wait.size() == 0 && !wait.nextDeadline());
}

void nameWaitGivesUpAfterTheWait() {
    // Una app que se conecta directo a una IP (o con DNS propio) nunca trae nombre: pregunta al vencer la espera.
    gbe::NameWait<Drop> wait(std::chrono::seconds(2), 10);
    const auto t0 = Clock::now();
    const auto never = [](const Drop &) { return false; };
    wait.hold({L"203.0.113.7"}, t0);
    check(L"marca la hora de vencimiento", wait.nextDeadline() && *wait.nextDeadline() == t0 + std::chrono::seconds(2));
    check(L"un instante antes de vencer, sigue esperando", wait.release(t0 + milliseconds(1999), never).empty());
    const auto out = wait.release(t0 + std::chrono::seconds(2), never);
    check(L"al vencer lo suelta", out.size() == 1);
    check(L"sin nombre se pregunta, como antes", out.size() == 1 && verdict(L"*.example.com", {}, out[0]) == L"ask");
}

void nameWaitKeepsOrderAndLimit() {
    gbe::NameWait<Drop> wait(std::chrono::seconds(2), 3);
    const auto t0 = Clock::now();
    // Los ocho intentos de Python a las ocho direcciones de un mismo nombre, en el mismo segundo.
    int held = 0;
    for (int i = 0; i < 8; ++i) held += wait.hold({L"172.217.11" + std::to_wstring(i) + L".4"}, t0) ? 1 : 0;
    check(L"con la cola llena el resto se decide ya (no se pierde)", held == 3 && wait.size() == 3);
    std::map<std::wstring, std::wstring> names{{L"172.217.111.4", L"www.googleapis.com"}};
    const auto out = wait.release(t0 + milliseconds(500), [&](const Drop &d) { return names.count(d.address) > 0; });
    check(L"suelta sólo los que ya tienen nombre", out.size() == 1 && out[0].address == L"172.217.111.4");
    const auto rest = wait.release(t0 + std::chrono::seconds(3), [](const Drop &) { return false; });
    check(L"el resto sale al vencer, en orden de llegada",
          rest.size() == 2 && rest[0].address == L"172.217.110.4" && rest[1].address == L"172.217.112.4");
}

void theReportedSequence() {
    // 20:50:12 se guarda «Allow python.exe to *.googleusercontent.com». 20:51:57 el intento a 142.251.129.129 llega al
    // motor antes que la consulta DNS. Antes: pedido sin nombre, el DNS lo borraba un instante después y el aviso se
    // cerraba solo. Ahora: el bloqueo espera el nombre y se resuelve por la regla, sin pedido.
    const std::wstring rule = L"*.googleusercontent.com";
    std::map<std::wstring, std::wstring> names;
    const Drop drop{L"142.251.129.129"};
    check(L"secuencia reportada, sin espera: se preguntaba", verdict(rule, names, drop) == L"ask");
    gbe::NameWait<Drop> wait(std::chrono::seconds(2), 10);
    const auto t0 = Clock::now();
    wait.hold(drop, t0);
    names[drop.address] = L"doc-04-34-sheets.googleusercontent.com";
    const auto out = wait.release(t0 + milliseconds(1000), [&](const Drop &d) { return names.count(d.address) > 0; });
    check(L"secuencia reportada, con espera: lo resuelve la regla",
          out.size() == 1 && verdict(rule, names, out[0]) == L"allow");
}

} // namespace

int wmain() {
    destinationMatchNeedsTheName();
    nameWaitReleasesWhenTheNameArrives();
    nameWaitGivesUpAfterTheWait();
    nameWaitKeepsOrderAndLimit();
    theReportedSequence();
    std::wprintf(failures ? L"\n%d FAILED\n" : L"\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
