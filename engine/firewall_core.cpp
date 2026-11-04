#include "firewall_core.h"
#include "destination_match.h"
#include "signature.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <set>
#include <sstream>

namespace gbe {
namespace {

constexpr std::uint8_t WeightAsk = 1;
constexpr std::uint8_t WeightAllowRule = 10;
constexpr std::uint8_t WeightBlockRule = 15; // le gana también a los permisos de servicios de Windows
// Un destino permitido le gana al Allow de la app entera de otra identidad (un editor) y pierde contra cualquier Block.
constexpr std::uint8_t WeightAllowDestination = 12;
constexpr std::uint8_t WeightBlockDestination = 15;
constexpr std::size_t GrantLimit = 5000;
constexpr std::size_t HintQueueLimit = 1000;
// Un permiso de destino al que la app no vuelve en una semana se retira (las IPs de un servicio cambian con el tiempo).
constexpr std::int64_t GrantIdleSeconds = 7 * 24 * 3600;
constexpr wchar_t DestinationSeparator = L'\x1f';
constexpr std::size_t ActivityLimit = 2000;
constexpr std::size_t PendingLimit = 500;
constexpr std::size_t VerifyQueueLimit = 1000;
constexpr std::size_t SignerCacheLimit = 2000;

std::uint8_t weightFor(Action action) { return action == Action::Allow ? WeightAllowRule : WeightBlockRule; }

std::string toUtf8(const std::wstring &w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring fromUtf8(const std::string &s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), w.data(), n);
    return w;
}

std::int64_t fileTimeToUnix(const FILETIME &ft) {
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    if (!u.QuadPart) return FirewallCore::now();
    return std::int64_t(u.QuadPart / 10000000ULL) - 11644473600LL;
}

std::vector<std::string> split(const std::string &line) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (;;) {
        const auto tab = line.find('\t', start);
        out.push_back(line.substr(start, tab == std::string::npos ? std::string::npos : tab - start));
        if (tab == std::string::npos) break;
        start = tab + 1;
    }
    return out;
}

bool isFile(const std::wstring &path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

// Sello con el que se detecta que un archivo cubierto cambió. La hora de cambio la mueve NTFS ante cualquier escritura
// (no la de escritura, que SetFileTime pone a gusto) y el id cambia si otro archivo ocupa la ruta.
bool stampOf(const std::wstring &path, FileStamp &stamp) {
    HANDLE file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    FILE_BASIC_INFO basic{};
    FILE_STANDARD_INFO standard{};
    FILE_ID_INFO id{};
    const bool ok = GetFileInformationByHandleEx(file, FileBasicInfo, &basic, sizeof(basic)) &&
                    GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard)) &&
                    !standard.Directory;
    // FileIdInfo puede no estar en todos los sistemas de archivos: sin id, el sello usa lo demás.
    const bool hasId = GetFileInformationByHandleEx(file, FileIdInfo, &id, sizeof(id));
    CloseHandle(file);
    if (!ok) return false;
    stamp.change = basic.ChangeTime.QuadPart;
    stamp.size = std::uint64_t(standard.EndOfFile.QuadPart);
    stamp.idLow = stamp.idHigh = 0;
    if (hasId) {
        std::memcpy(&stamp.idLow, id.FileId.Identifier, 8);
        std::memcpy(&stamp.idHigh, id.FileId.Identifier + 8, 8);
    }
    return true;
}

constexpr auto CoverageRecheck = std::chrono::seconds(60);
// Cada tanto se verifica la firma de todo lo cubierto aunque el sello no haya cambiado.
constexpr int FullRecheckEvery = 10; // vueltas de CoverageRecheck
// Las reglas temporales se revisan con esta frecuencia: vencen con hasta este retraso.
constexpr auto ExpiryCheck = std::chrono::seconds(10);

// Texto del historial para una regla por firma o por destino.
std::wstring describe(const Rule &rule) {
    const std::wstring who = rule.scope == Scope::App         ? L"any version of " + rule.name + L" from " + rule.signer
                             : rule.scope == Scope::Publisher ? L"all apps from " + rule.signer
                                                              : FirewallCore::fileName(rule.path);
    return rule.destination.empty() ? who : who + L" to " + rule.destination;
}

// Texto del historial para la duración de una decisión: vacío si es permanente.
std::wstring describeExpiry(std::int64_t expires, std::int64_t from) {
    if (expires == UntilRestart) return L" until restart";
    if (expires <= 0) return L"";
    const auto minutes = (expires - from + 30) / 60;
    return minutes >= 60 && minutes % 60 == 0 ? L" for " + std::to_wstring(minutes / 60) + (minutes == 60 ? L" hour" : L" hours")
                                              : L" for " + std::to_wstring(minutes) + L" minutes";
}

} // namespace

FirewallCore::FirewallCore(CoreOptions options) : options_(std::move(options)) {}

FirewallCore::~FirewallCore() { stop(); }

std::wstring FirewallCore::key(const std::wstring &path) {
    std::wstring k = path;
    std::transform(k.begin(), k.end(), k.begin(), [](wchar_t c) { return wchar_t(std::towlower(c)); });
    return k;
}

std::wstring FirewallCore::fileName(const std::wstring &path) {
    const auto slash = path.find_last_of(L"\\/");
    return key(slash == std::wstring::npos ? path : path.substr(slash + 1));
}

std::wstring FirewallCore::identityKey(const Rule &rule) {
    // Las rutas empiezan con letra de unidad o barra: nunca chocan con estas claves.
    if (rule.scope == Scope::App) return L"app|" + key(rule.signer) + L"|" + rule.name;
    if (rule.scope == Scope::Publisher) return L"publisher|" + key(rule.signer);
    return key(rule.path);
}

std::wstring FirewallCore::ruleKey(const Rule &rule) {
    // «|» no puede ir en una ruta ni en un destino válido.
    return rule.destination.empty() ? identityKey(rule) : identityKey(rule) + L"|dest|" + rule.destination;
}

std::wstring FirewallCore::normalizeDestination(const std::wstring &destination) {
    std::wstring d = key(destination);
    while (!d.empty() && iswspace(d.back())) d.pop_back();
    while (!d.empty() && iswspace(d.front())) d.erase(d.begin());
    while (!d.empty() && d.back() == L'.') d.pop_back();
    if (d.empty() || d.size() > 253) return {};
    const std::wstring ip = DnsNames::normalize(d);
    if (!ip.empty()) return ip;
    const bool wildcard = d.rfind(L"*.", 0) == 0;
    const std::wstring host = wildcard ? d.substr(2) : d;
    // Un nombre con al menos dos partes: «*.com» abriría medio internet.
    if (host.find(L'.') == std::wstring::npos) return {};
    std::size_t label = 0;
    for (const wchar_t c : host) {
        if (c == L'.') {
            if (label == 0) return {};
            label = 0;
        } else if ((c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') || c == L'-' || c == L'_') {
            if (++label > 63) return {};
        } else {
            return {};
        }
    }
    return label == 0 ? std::wstring() : d;
}

std::int64_t FirewallCore::now() {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return std::int64_t(u.QuadPart / 10000000ULL) - 11644473600LL;
}

bool FirewallCore::start(std::wstring &error) {
    std::lock_guard<std::mutex> lock(mutex_);
    load();
    if (!wfp_.open(options_.dynamic, error) || !wfp_.ensureObjects(error)) return false;
    // Un arranque reconstruye todo desde las reglas guardadas en UNA transacción: si algo falla, quedan los filtros
    // anteriores tal cual y nunca un bloqueo general sin sus permisos de base.
    if (!wfp_.begin(error)) return false;
    bool ok = options_.dynamic || wfp_.removeAllOwnFilters(error);
    if (ok && options_.scope.empty()) ok = wfp_.addSystemAllowances(systemFilters_, error);
    if (ok && localNetwork_) ok = wfp_.addLocalNetworkPermit(localFilters_, error);
    std::size_t skipped = 0;
    for (auto &[k, rule] : rules_) {
        if (!ok) break;
        if (rule.scope != Scope::Path || !rule.destination.empty()) continue;
        // Un ejecutable que ya no existe (desinstalado, actualizado, disco sin montar) no frena el arranque:
        // su regla queda guardada y, mientras falte, esa ruta vuelve a preguntar.
        if (!isFile(rule.path)) {
            ++skipped;
            continue;
        }
        std::wstring ruleError;
        if (!installRule(rule, ruleError)) {
            if (ruleError.rfind(L"FwpmGetAppIdFromFileName0", 0) == 0) {
                ++skipped;
                continue;
            }
            error = ruleError;
            ok = false;
        }
    }
    // Coberturas de reglas por firma: el archivo se vuelve a verificar. Si cambió de firmante, falta o ya tiene una
    // regla propia, la cobertura se descarta y esa ruta vuelve a pasar por la verificación en su próximo bloqueo.
    for (auto it = covered_.begin(); ok && it != covered_.end();) {
        const auto rule = rules_.find(it->second.ruleKey);
        const auto own = rules_.find(it->first);
        if (rule == rules_.end() || rule->second.scope == Scope::Path || own != rules_.end() ||
            !stampOf(it->second.path, it->second.stamp) ||
            !matches(rule->second, it->second.path, signerOf(it->second.path))) {
            it = covered_.erase(it);
            continue;
        }
        std::wstring coverError;
        it->second.filters.clear();
        if (!wfp_.addAppFilter(it->second.path, rule->second.action, Direction::Outbound,
                               weightFor(rule->second.action), it->second.filters, coverError)) {
            if (coverError.rfind(L"FwpmGetAppIdFromFileName0", 0) == 0) {
                it = covered_.erase(it);
                continue;
            }
            error = coverError;
            ok = false;
            break;
        }
        ++it;
    }
    // Permisos de destino: la misma revisión que las coberturas. Los de una regla por firma que permite se vuelven a
    // verificar; los que la app no usó en una semana no vuelven.
    for (auto it = grants_.begin(); ok && it != grants_.end();) {
        const auto rule = rules_.find(it->second.ruleKey);
        const bool verify = rule != rules_.end() && rule->second.scope != Scope::Path && rule->second.action == Action::Allow;
        if (rule == rules_.end() || rule->second.destination.empty() ||
            (rules_.count(key(it->second.path)) && rule->second.action == Action::Allow) ||
            now() - it->second.lastSeen > GrantIdleSeconds || !isFile(it->second.path) ||
            (verify && (!stampOf(it->second.path, it->second.stamp) ||
                        !matches(rule->second, it->second.path, signerOf(it->second.path))))) {
            it = grants_.erase(it);
            continue;
        }
        std::wstring grantError;
        it->second.filters.clear();
        if (!wfp_.addAppAddressFilter(it->second.path, it->second.address, rule->second.action,
                                      rule->second.action == Action::Allow ? WeightAllowDestination : WeightBlockDestination,
                                      it->second.filters, grantError)) {
            if (grantError.rfind(L"FwpmGetAppIdFromFileName0", 0) == 0 || grantError.rfind(L"Invalid address", 0) == 0) {
                it = grants_.erase(it);
                continue;
            }
            error = grantError;
            ok = false;
            break;
        }
        it->second.action = rule->second.action;
        ++it;
    }
    if (ok && ask_) ok = applyAskFilters(error);
    if (!ok) {
        wfp_.abort();
        return false;
    }
    if (!wfp_.commit(error)) return false;
    // Permiso HTTPS de la ventana en su propia transacción, después del arranque: si falla, el motor arranca igual
    // (sólo faltan las explicaciones) y una ventana que ya no existe tampoco lo frena.
    for (const auto &window : options_.windows)
        if (options_.scope.empty() && isFile(window)) {
            std::wstring windowError;
            if (!wfp_.addHttpsPermit(window, systemFilters_, windowError))
                lastError_ += std::wstring(lastError_.empty() ? L"" : L"; ") + L"Window HTTPS permit: " + windowError;
        }
    if (skipped)
        lastError_ += (lastError_.empty() ? L"" : L"; ") + std::to_wstring(skipped) +
                      L" rules skipped: executable not found";
    // Nombres de destino: si ETW no está disponible el motor funciona igual, sólo sin nombres en el aviso.
    std::wstring dnsError;
    dns_.setListener([this](const std::wstring &app, const std::wstring &host, const std::vector<std::wstring> &addresses) {
        onResolved(app, host, addresses);
    });
    const std::wstring dnsSession = options_.dynamic ? TestSessionPrefix + std::to_wstring(GetCurrentProcessId())
                                                     : std::wstring(L"LGA GateBouncer DNS");
    if (!dns_.start(dnsSession, dnsError))
        lastError_ += (lastError_.empty() ? L"" : L"; ") + std::wstring(L"Destination names unavailable: ") + dnsError;
    verifyStop_ = false;
    verifyThread_ = std::thread([this] { verifyLoop(); });
    if (!wfp_.subscribeDrops([this](const DropEvent &d) { onDrop(d); }, error)) return false;
    started_ = now();
    return true;
}

void FirewallCore::stop() {
    // Sin el mutex propio: el hilo de verificación lo toma, y cerrar la suscripción espera a que terminen los avisos
    // en curso. Primero termina la verificación, para que nada agregue filtros a un motor que se cierra.
    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        verifyStop_ = true;
    }
    verifyWake_.notify_all();
    if (verifyThread_.joinable()) verifyThread_.join();
    dns_.stop();
    wfp_.close();
    std::lock_guard<std::mutex> lock(mutex_);
    // El último uso de los permisos de destino sólo se guarda con otros cambios: al cerrar se deja al día, así un
    // permiso usado a diario no se descarta por viejo en el próximo arranque.
    if (!grants_.empty()) {
        std::wstring error;
        save(error);
    }
    askFilters_.clear();
    systemFilters_.clear();
    localFilters_.clear();
    for (auto &[k, rule] : rules_) rule.filters.clear();
    for (auto &[k, c] : covered_) c.filters.clear();
    for (auto &[k, g] : grants_) g.filters.clear();
}

bool FirewallCore::applyAskFilters(std::wstring &error) {
    if (options_.scope.empty()) return wfp_.addDefaultBlock(Direction::Outbound, askFilters_, error);
    for (const auto &path : options_.scope)
        if (!wfp_.addAppFilter(path, Action::Block, Direction::Outbound, WeightAsk, askFilters_, error)) return false;
    return true;
}

bool FirewallCore::removeAskFilters(std::wstring &error) {
    if (!wfp_.begin(error)) return false;
    for (auto id : askFilters_) wfp_.removeFilter(id);
    if (!wfp_.commit(error)) return false;
    askFilters_.clear();
    return true;
}

bool FirewallCore::installRule(Rule &rule, std::wstring &error) {
    for (auto id : rule.filters) wfp_.removeFilter(id);
    rule.filters.clear();
    return wfp_.addAppFilter(rule.path, rule.action, Direction::Outbound, weightFor(rule.action), rule.filters, error);
}

bool FirewallCore::matches(const Rule &rule, const std::wstring &path, const std::wstring &signer) const {
    if (rule.scope == Scope::Path || signer.empty() || key(rule.signer) != key(signer)) return false;
    return rule.scope == Scope::Publisher || rule.name == fileName(path);
}

const Rule *FirewallCore::signerRuleFor(const std::wstring &path, const std::wstring &signer) const {
    if (signer.empty()) return nullptr;
    // La regla de la app le gana a la del editor: permitir todo un editor no deshace un Block puntual.
    Rule probe;
    probe.scope = Scope::App;
    probe.signer = signer;
    probe.name = fileName(path);
    auto it = rules_.find(ruleKey(probe));
    if (it != rules_.end()) return &it->second;
    probe.scope = Scope::Publisher;
    it = rules_.find(ruleKey(probe));
    return it != rules_.end() ? &it->second : nullptr;
}

bool FirewallCore::identityMatches(const Rule &rule, const std::wstring &path, const std::wstring &signer) const {
    return rule.scope == Scope::Path ? key(rule.path) == key(path) : matches(rule, path, signer);
}

const Rule *FirewallCore::destinationRuleFor(const std::wstring &path, const std::wstring &signer,
                                             const std::wstring &host, const std::wstring &address, bool &any) const {
    any = false;
    if (destinationRules_ <= 0) return nullptr;
    const Rule *best = nullptr;
    std::size_t bestScore = 0;
    for (const auto &[k, r] : rules_) {
        if (r.destination.empty() || !identityMatches(r, path, signer)) continue;
        any = true;
        const auto score = destinationMatch(r.destination, host, address);
        // A igual especificidad gana el Block: si dos reglas no se ponen de acuerdo, se cierra.
        if (score > bestScore || (score && score == bestScore && r.action == Action::Block)) {
            best = &r;
            bestScore = score;
        }
    }
    return best;
}

bool FirewallCore::grant(const std::wstring &path, const std::wstring &address, const Rule &rule,
                         const FileStamp &stamp, std::wstring &error, bool *changed) {
    if (changed) *changed = false;
    const std::wstring a = DnsNames::normalize(address);
    if (a.empty()) {
        error = L"Invalid address";
        return false;
    }
    const auto gk = key(path) + DestinationSeparator + a;
    const auto rk = ruleKey(rule);
    const auto old = grants_.find(gk);
    if (old != grants_.end() && !old->second.filters.empty()) {
        // Ya está, o una IP compartida por dos destinos (una CDN): si uno la bloqueó, sigue bloqueada.
        const bool same = old->second.ruleKey == rk && old->second.action == rule.action;
        const bool keepBlock = old->second.action == Action::Block && rule.action == Action::Allow &&
                               rules_.count(old->second.ruleKey);
        if (same || keepBlock) {
            old->second.lastSeen = now();
            return true;
        }
    }
    if (old == grants_.end() && grants_.size() >= GrantLimit) {
        error = L"Too many destination permits";
        return false;
    }
    std::vector<std::uint64_t> ids;
    if (!wfp_.begin(error)) return false;
    if (!wfp_.addAppAddressFilter(path, a, rule.action,
                                  rule.action == Action::Allow ? WeightAllowDestination : WeightBlockDestination, ids,
                                  error)) {
        wfp_.abort();
        return false;
    }
    if (old != grants_.end())
        for (auto id : old->second.filters) wfp_.removeFilter(id);
    if (!wfp_.commit(error)) return false;
    Grant g;
    g.path = path;
    g.address = a;
    g.ruleKey = rk;
    g.action = rule.action;
    g.filters = ids;
    g.stamp = stamp;
    g.lastSeen = now();
    grants_[gk] = g;
    if (changed) *changed = true;
    return true;
}

void FirewallCore::eraseGrantsOf(const std::wstring &rk) {
    std::wstring error;
    if (!wfp_.begin(error)) return;
    for (const auto &[gk, g] : grants_)
        if (g.ruleKey == rk)
            for (auto id : g.filters) wfp_.removeFilter(id);
    if (!wfp_.commit(error)) {
        lastError_ = L"Could not withdraw destination permits: " + error;
        return;
    }
    for (auto g = grants_.begin(); g != grants_.end();) g = g->second.ruleKey == rk ? grants_.erase(g) : std::next(g);
}

void FirewallCore::erasePendingOf(const std::wstring &pathKey) {
    pending_.erase(pathKey);
    const std::wstring prefix = pathKey + DestinationSeparator;
    for (auto p = pending_.lower_bound(prefix); p != pending_.end() && p->first.rfind(prefix, 0) == 0;)
        p = pending_.erase(p);
}

void FirewallCore::onResolved(const std::wstring &app, const std::wstring &host,
                              const std::vector<std::wstring> &addresses) {
    // Hilo de ETW: sólo se encola. Sin reglas por destino no hace falta mirar el DNS.
    if (destinationRules_ <= 0) return;
    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        if (hintQueue_.size() >= HintQueueLimit) return;
        hintQueue_.push_back({app, host, addresses});
    }
    verifyWake_.notify_one();
}

void FirewallCore::applyHint(const DnsHint &hint) {
    // La app resolvió un nombre: si una regla por destino lo cubre, el permiso de cada IP se pone ya, así el intento
    // que viene detrás suele pasar (o quedar bloqueado sin aviso).
    const auto k = key(hint.app);
    // Primero, sin verificar nada: si ninguna regla por destino puede ser de esta app, no se mira su firma.
    bool signerRules = false, pathRules = false;
    const std::wstring name = fileName(hint.app);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto &[rk, r] : rules_) {
            if (r.destination.empty()) continue;
            if (r.scope == Scope::Path) pathRules = pathRules || key(r.path) == k;
            else signerRules = signerRules || r.scope == Scope::Publisher || r.name == name;
        }
    }
    if (!signerRules && !pathRules) return;
    const std::wstring cached = signerRules ? cachedSigner(hint.app) : std::wstring();
    bool needFresh = false, any = false;
    std::vector<std::wstring> covered;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Con una regla de la app entera sólo cuentan los Block por destino: el Block gana (peso 15 contra 10).
        const bool whole = rules_.count(k) > 0;
        for (const auto &a : hint.addresses) {
            const Rule *r = destinationRuleFor(hint.app, cached, hint.host, a, any);
            if (!any) return;
            if (!r || (whole && r->action == Action::Allow)) continue;
            covered.push_back(a);
            if (r->action == Action::Allow && r->scope != Scope::Path) needFresh = true;
        }
    }
    if (covered.empty()) return;
    const std::wstring path = WfpEngine::withRealCase(hint.app);
    FileStamp stamp;
    std::wstring signer = cached;
    // Antes de abrir algo por firma, la firma se verifica de nuevo sobre el archivo actual.
    if (needFresh) signer = stampOf(path, stamp) ? signerOf(path) : std::wstring();
    std::lock_guard<std::mutex> lock(mutex_);
    const bool whole = rules_.count(k) > 0;
    bool changed = false;
    for (const auto &a : covered) {
        const Rule *r = destinationRuleFor(path, signer, hint.host, a, any);
        if (!r || (whole && r->action == Action::Allow)) continue;
        // Una regla Allow por firma que apareció entre las dos miradas no se concede sin verificar la firma.
        if (r->action == Action::Allow && r->scope != Scope::Path && !needFresh) continue;
        std::wstring error;
        bool added = false;
        if (!grant(path, a, *r, stamp, error, &added)) {
            lastError_ = L"Could not apply " + describe(*r) + L": " + error;
            continue;
        }
        changed = changed || added;
        const auto asked = pending_.find(k + DestinationSeparator + a);
        if (asked != pending_.end()) {
            // El pedido se anotó antes de que llegara el nombre (la espera de nameWait_ venció): la regla lo resuelve y
            // el historial lo dice, para que no quede sólo «waiting for decision» de algo que ya no se pregunta.
            addGrantActivity(now(), asked->second.path, a, *r, asked->second.remoteAddress, asked->second.remotePort,
                             asked->second.protocol);
            pending_.erase(asked);
        }
    }
    std::wstring error;
    if (changed) save(error);
}

bool FirewallCore::setAsk(bool ask, std::wstring &error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (ask == ask_) return true;
    if (ask) {
        if (!applyAskFilters(error)) return false;
    } else if (!removeAskFilters(error)) {
        return false;
    }
    ask_ = ask;
    addActivity({now(), L"", ask ? L"Asking for unknown applications" : L"Unknown applications allowed", L"", 0, 0});
    return save(error);
}

bool FirewallCore::setLocalNetwork(bool allow, std::wstring &error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (allow == localNetwork_) return true;
    if (allow) {
        if (!wfp_.addLocalNetworkPermit(localFilters_, error)) return false;
    } else {
        if (!wfp_.begin(error)) return false;
        for (auto id : localFilters_)
            if (!wfp_.removeFilter(id)) {
                // Todo o nada: un filtro que no se pudo quitar seguiría permitiendo la red local sin que se sepa.
                wfp_.abort();
                error = L"Could not remove the local network permit";
                return false;
            }
        if (!wfp_.commit(error)) return false;
        localFilters_.clear();
    }
    localNetwork_ = allow;
    addActivity({now(), L"", allow ? L"Local network allowed without asking" : L"Asking for local network connections",
                 L"", 0, 0});
    return save(error);
}

bool FirewallCore::decide(const std::wstring &path, Action action, Scope scope, std::wstring &error,
                          std::int64_t expires, const std::wstring &destination) {
    if (path.empty() || path.find_first_of(L"\t\r\n|") != std::wstring::npos) {
        error = L"Invalid application path";
        return false;
    }
    if (expires != 0 && expires != UntilRestart && expires <= now()) {
        error = L"Invalid duration";
        return false;
    }
    if (!destination.empty()) return decideDestination(path, action, scope, destination, expires, error);
    const auto k = key(path);
    // Un pendiente cuyo ejecutable ya no está (instalador temporal, app actualizada) no se puede decidir: se descarta.
    // El sello se toma ANTES de verificar la firma: un cambio entre las dos cosas queda como archivo cambiado.
    FileStamp stamp;
    if (!stampOf(path, stamp)) {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.erase(k);
        error = L"This application no longer exists.";
        return false;
    }
    // La firma se verifica antes de tomar el mutex: puede tardar y el motor sigue atendiendo bloqueos.
    std::wstring signer;
    if (scope != Scope::Path) {
        signer = signerOf(path);
        if (signer.empty()) {
            error = L"This application has no valid signature. Use This file only.";
            return false;
        }
        if (scope == Scope::Publisher && !publisherRuleAllowed(signer)) {
            error = L"All apps from " + signer + L" would include Windows tools. Use This app, any version.";
            return false;
        }
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (scope == Scope::Path) {
        Rule rule;
        auto existing = rules_.find(k);
        if (existing != rules_.end()) rule = existing->second;
        rule.scope = Scope::Path;
        rule.path = existing != rules_.end() ? existing->second.path : path;
        if (rule.action != action || existing == rules_.end()) rule.created = now();
        rule.action = action;
        rule.expires = expires;
        // Regla nueva y retiro de la vieja en una sola transacción: nunca hay un hueco ni dos reglas.
        Rule fresh = rule;
        fresh.filters.clear();
        if (!wfp_.begin(error)) return false;
        if (!wfp_.addAppFilter(fresh.path, action, Direction::Outbound, weightFor(action), fresh.filters, error)) {
            wfp_.abort();
            return false;
        }
        for (auto id : rule.filters) wfp_.removeFilter(id);
        // Una regla de ruta reemplaza la cobertura que esa ruta tuviera por una regla de firma.
        const auto cov = covered_.find(k);
        if (cov != covered_.end())
            for (auto id : cov->second.filters) wfp_.removeFilter(id);
        if (!wfp_.commit(error)) return false;
        if (cov != covered_.end()) covered_.erase(cov);
        rules_[k] = fresh;
        dropDestinationRulesOf(k);
        erasePendingOf(k);
        addActivity({now(), fresh.path,
                     (action == Action::Allow ? L"Rule saved: Allow" : L"Rule saved: Block") + describeExpiry(expires, now()),
                     L"", 0, 0});
        return save(error);
    }

    Rule rule;
    rule.scope = scope;
    rule.signer = signer;
    rule.name = scope == Scope::App ? fileName(path) : std::wstring();
    rule.action = action;
    const auto rk = ruleKey(rule);
    const auto existing = rules_.find(rk);
    rule.created = existing != rules_.end() && existing->second.action == action ? existing->second.created : now();
    rule.lastBlock = existing != rules_.end() ? existing->second.lastBlock : 0;
    rule.expires = expires;
    // Rutas que pasan a esta regla ya: la decidida (su firma se acaba de verificar) y las que la regla ya cubría (cambia
    // la acción). Las que tienen regla de ruta se respetan, y una regla de editor no pisa la de una app concreta. Los
    // otros pendientes que coinciden salen de la lista y se cubren en su próximo intento, con la firma verificada de
    // nuevo en ese momento: la del pendiente pudo cambiar desde que se anotó.
    const auto yieldsToApp = [&](const std::wstring &candidate) {
        if (scope != Scope::Publisher) return false;
        Rule probe = rule;
        probe.scope = Scope::App;
        probe.name = fileName(candidate);
        return rules_.count(ruleKey(probe)) > 0;
    };
    std::map<std::wstring, std::wstring> targets; // clave -> ruta
    if (!rules_.count(k) && !yieldsToApp(path)) targets[k] = path;
    for (auto c = covered_.begin(); c != covered_.end();) {
        if (c->second.ruleKey != rk) {
            ++c;
        } else if (!isFile(c->second.path)) {
            // Un archivo cubierto que ya no está no frena la decisión: su filtro se retira con ella.
            for (auto id : c->second.filters) wfp_.removeFilter(id);
            c = covered_.erase(c);
        } else {
            targets[c->first] = c->second.path;
            ++c;
        }
    }
    std::map<std::wstring, std::vector<std::uint64_t>> fresh;
    if (!wfp_.begin(error)) return false;
    for (const auto &[tk, target] : targets) {
        auto &ids = fresh[tk];
        if (!wfp_.addAppFilter(target, action, Direction::Outbound, weightFor(action), ids, error)) {
            wfp_.abort();
            return false;
        }
        const auto old = covered_.find(tk);
        if (old != covered_.end())
            for (auto id : old->second.filters) wfp_.removeFilter(id);
    }
    if (!wfp_.commit(error)) return false;
    for (const auto &[tk, target] : targets) {
        // La decidida lleva el sello tomado antes de verificarla; las que ya estaban cubiertas conservan el suyo (no se
        // re-verificaron ahora, así que un sello nuevo las daría por buenas).
        Covered c{target, rk, fresh[tk]};
        const auto old = covered_.find(tk);
        c.stamp = tk == k ? stamp : old != covered_.end() ? old->second.stamp : FileStamp{};
        covered_[tk] = c;
        erasePendingOf(tk);
    }
    for (auto p = pending_.begin(); p != pending_.end();)
        p = !rules_.count(key(p->second.path)) && matches(rule, p->second.path, p->second.signer) &&
                    !yieldsToApp(p->second.path)
                ? pending_.erase(p)
                : std::next(p);
    rules_[rk] = rule;
    dropDestinationRulesOf(rk);
    addActivity({now(), path,
                 (action == Action::Allow ? L"Rule saved: Allow " : L"Rule saved: Block ") + describe(rule) +
                     describeExpiry(expires, now()),
                 L"", 0, 0});
    return save(error);
}

bool FirewallCore::decideDestination(const std::wstring &path, Action action, Scope scope,
                                     const std::wstring &destination, std::int64_t expires, std::wstring &error) {
    const std::wstring dest = normalizeDestination(destination);
    if (dest.empty()) {
        error = L"Invalid destination: use a server name, *.domain or an IP address";
        return false;
    }
    const auto k = key(path);
    FileStamp stamp;
    if (!stampOf(path, stamp)) {
        std::lock_guard<std::mutex> lock(mutex_);
        erasePendingOf(k);
        error = L"This application no longer exists.";
        return false;
    }
    std::wstring signer;
    if (scope != Scope::Path) {
        signer = signerOf(path);
        if (signer.empty()) {
            error = L"This application has no valid signature. Use This file only.";
            return false;
        }
        if (scope == Scope::Publisher && !publisherRuleAllowed(signer)) {
            error = L"All apps from " + signer + L" would include Windows tools. Use This app, any version.";
            return false;
        }
    }
    Rule rule;
    rule.scope = scope;
    rule.path = scope == Scope::Path ? path : std::wstring();
    rule.signer = signer;
    rule.name = scope == Scope::App ? fileName(path) : std::wstring();
    rule.destination = dest;
    rule.action = action;
    rule.expires = expires;
    std::lock_guard<std::mutex> lock(mutex_);
    const auto rk = ruleKey(rule);
    // La app entera de esta identidad pasa a modo por destino: su regla deja de valer.
    const auto whole = rules_.find(identityKey(rule));
    if (whole != rules_.end() && !dropRule(whole, L"Rule replaced by destination rules", error)) return false;
    const auto existing = rules_.find(rk);
    if (existing != rules_.end()) {
        rule.created = existing->second.action == action ? existing->second.created : now();
        rule.lastBlock = existing->second.lastBlock;
        // Cambió la acción: los permisos de destino viejos se rehacen con la nueva en el próximo intento.
        if (existing->second.action != action) eraseGrantsOf(rk);
    } else {
        rule.created = now();
        ++destinationRules_;
    }
    rules_[rk] = rule;
    // Pendientes que esta regla resuelve. El de la app decidida recibe el permiso ya (su firma se acaba de verificar);
    // los de otras rutas de la misma identidad se cubren en su próximo intento, con la firma verificada entonces.
    for (auto p = pending_.begin(); p != pending_.end();) {
        const auto pk = key(p->second.path);
        const bool mine = pk == k;
        if (!mine && (rules_.count(pk) || !identityMatches(rule, p->second.path, p->second.signer))) {
            ++p;
            continue;
        }
        const std::wstring address = DnsNames::normalize(p->second.remoteAddress);
        const std::wstring host = p->second.host.empty() ? dns_.nameFor(address, pk) : p->second.host;
        if (!destinationMatch(dest, host, address)) {
            // La app decidida ya no pregunta por la app entera: lo que quede vuelve a preguntar por destino.
            p = mine && !p->second.perDestination ? pending_.erase(p) : std::next(p);
            continue;
        }
        if (mine) {
            std::wstring grantError;
            if (!grant(path, address, rule, stamp, grantError))
                lastError_ = L"Could not apply " + describe(rule) + L": " + grantError;
        }
        p = pending_.erase(p);
    }
    addActivity({now(), path,
                 (action == Action::Allow ? L"Rule saved: Allow " : L"Rule saved: Block ") + describe(rule) +
                     describeExpiry(expires, now()),
                 L"", 0, 0});
    return save(error);
}

void FirewallCore::dropDestinationRulesOf(const std::wstring &identity) {
    for (auto it = rules_.begin(); it != rules_.end();) {
        if (it->second.destination.empty() || identityKey(it->second) != identity) {
            ++it;
            continue;
        }
        auto next = std::next(it);
        std::wstring error;
        if (!dropRule(it, L"Destination rule replaced", error)) lastError_ = L"Could not remove a destination rule: " + error;
        it = next;
    }
}

bool FirewallCore::removeRule(const std::wstring &id, std::wstring &error) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(key(id));
    if (it == rules_.end()) {
        error = L"No rule for this application";
        return false;
    }
    return dropRule(it, L"Rule removed", error) && save(error);
}

bool FirewallCore::dropRule(std::map<std::wstring, Rule>::iterator it, const std::wstring &reason, std::wstring &error) {
    // Todo en una transacción: si falla, la regla queda entera y se reintenta después.
    if (!wfp_.begin(error)) return false;
    if (!it->second.destination.empty()) {
        // Regla por destino: se retiran sus permisos de destino; esas IPs vuelven a preguntar.
        for (const auto &[gk, g] : grants_)
            if (g.ruleKey == it->first)
                for (auto fid : g.filters) wfp_.removeFilter(fid);
        if (!wfp_.commit(error)) return false;
        for (auto g = grants_.begin(); g != grants_.end();) g = g->second.ruleKey == it->first ? grants_.erase(g) : std::next(g);
        addActivity({now(), it->second.path, reason + L": " + describe(it->second), L"", 0, 0});
        rules_.erase(it);
        --destinationRules_;
        return true;
    }
    if (it->second.scope == Scope::Path) {
        for (auto fid : it->second.filters) wfp_.removeFilter(fid);
    } else {
        // Las rutas que cubría vuelven a preguntar (o a otra regla de firma que coincida) en su próximo bloqueo.
        for (const auto &[ck, c] : covered_)
            if (c.ruleKey == it->first)
                for (auto fid : c.filters) wfp_.removeFilter(fid);
    }
    if (!wfp_.commit(error)) return false;
    if (it->second.scope == Scope::Path) {
        addActivity({now(), it->second.path, reason, L"", 0, 0});
    } else {
        for (auto c = covered_.begin(); c != covered_.end();)
            c = c->second.ruleKey == it->first ? covered_.erase(c) : std::next(c);
        addActivity({now(), L"", reason + L": " + describe(it->second), L"", 0, 0});
    }
    rules_.erase(it);
    return true;
}

void FirewallCore::expireRules() {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto t = now();
    bool changed = false;
    for (auto it = rules_.begin(); it != rules_.end();) {
        if (it->second.expires <= 0 || it->second.expires > t) {
            ++it;
            continue;
        }
        auto next = std::next(it);
        std::wstring error;
        if (dropRule(it, L"Rule expired", error)) {
            changed = true;
        } else {
            lastError_ = L"Could not withdraw an expired rule: " + error;
        }
        it = next;
    }
    // Pedidos que nadie decidió en un día: si la app vuelve a intentar, pregunta de nuevo. Así la lista no se llena de
    // destinos viejos (hay un pedido por dirección en modo por destino).
    for (auto p = pending_.begin(); p != pending_.end();) p = t - p->second.last > 24 * 3600 ? pending_.erase(p) : std::next(p);
    // Permisos de destino sin uso en una semana: las IPs de un servicio cambian y no conviene acumularlas.
    std::vector<std::wstring> idle;
    for (const auto &[gk, g] : grants_)
        if (t - g.lastSeen > GrantIdleSeconds) idle.push_back(gk);
    if (!idle.empty()) {
        std::wstring error;
        if (wfp_.begin(error)) {
            for (const auto &gk : idle)
                for (auto id : grants_[gk].filters) wfp_.removeFilter(id);
            if (wfp_.commit(error)) {
                for (const auto &gk : idle) grants_.erase(gk);
                changed = true;
            }
        }
    }
    std::wstring error;
    if (changed) save(error);
}

void FirewallCore::onDrop(const DropEvent &drop) {
    if (drop.appPath.empty()) return;
    std::lock_guard<std::mutex> lock(mutex_);
    const auto k = key(drop.appPath);
    const auto t = fileTimeToUnix(drop.time);
    auto rule = rules_.find(k);
    const bool byRule = rule != rules_.end() && rule->second.action == Action::Block &&
                        std::find(rule->second.filters.begin(), rule->second.filters.end(), drop.filterId) !=
                            rule->second.filters.end();
    if (byRule) {
        rule->second.lastBlock = t;
        addActivity({t, rule->second.path, L"Blocked by rule", drop.remoteAddress, drop.remotePort, drop.protocol});
        return;
    }
    const auto cov = covered_.find(k);
    if (cov != covered_.end() &&
        std::find(cov->second.filters.begin(), cov->second.filters.end(), drop.filterId) != cov->second.filters.end()) {
        const auto owner = rules_.find(cov->second.ruleKey);
        if (owner != rules_.end()) {
            owner->second.lastBlock = t;
            addActivity({t, cov->second.path, L"Blocked by rule: " + describe(owner->second), drop.remoteAddress,
                         drop.remotePort, drop.protocol});
        }
        return;
    }
    const auto g = grants_.find(k + DestinationSeparator + DnsNames::normalize(drop.remoteAddress));
    if (g != grants_.end() &&
        std::find(g->second.filters.begin(), g->second.filters.end(), drop.filterId) != g->second.filters.end()) {
        const auto owner = rules_.find(g->second.ruleKey);
        if (owner != rules_.end()) {
            owner->second.lastBlock = t;
            g->second.lastSeen = t;
            addActivity({t, drop.appPath, L"Blocked by rule: " + describe(owner->second), drop.remoteAddress,
                         drop.remotePort, drop.protocol});
        }
        return;
    }
    if (std::find(askFilters_.begin(), askFilters_.end(), drop.filterId) == askFilters_.end()) return;
    // Carrera: la regla se guardó mientras el aviso viajaba. Una regla sin filtros es la que se omitió al arrancar
    // porque faltaba el ejecutable: su app volvió, así que se pregunta de nuevo y la decisión la reinstala.
    if (rule != rules_.end() && !rule->second.filters.empty()) return;
    if (cov != covered_.end() && !cov->second.filters.empty()) return;
    {
        std::lock_guard<std::mutex> queue(verifyMutex_);
        if (verifyQueue_.size() >= VerifyQueueLimit) return;
        verifyQueue_.push_back(drop);
    }
    verifyWake_.notify_one();
}

void FirewallCore::verifyLoop() {
    auto nextRecheck = std::chrono::steady_clock::now() + CoverageRecheck;
    for (;;) {
        DropEvent drop;
        DnsHint hint;
        bool hasDrop = false, hasHint = false;
        {
            std::unique_lock<std::mutex> lock(verifyMutex_);
            auto wake = std::min(nextRecheck, std::chrono::steady_clock::now() + ExpiryCheck);
            // Un bloqueo que espera su nombre se decide al vencer la espera aunque no llegue nada más.
            if (const auto held = nameWait_.nextDeadline()) wake = std::min(wake, *held);
            verifyWake_.wait_until(lock, wake,
                                   [this] { return verifyStop_ || !verifyQueue_.empty() || !hintQueue_.empty(); });
            if (verifyStop_) return;
            // Las consultas DNS primero: el permiso tiene que estar antes de que llegue el intento de conexión.
            if (!hintQueue_.empty()) {
                hint = std::move(hintQueue_.front());
                hintQueue_.pop_front();
                hasHint = true;
            } else if (!verifyQueue_.empty()) {
                drop = std::move(verifyQueue_.front());
                verifyQueue_.pop_front();
                hasDrop = true;
            }
        }
        if (hasHint) applyHint(hint);
        if (hasDrop) classify(drop, cachedSigner(drop.appPath));
        // Los que esperaban un nombre: ya llegó (la consulta DNS se procesó arriba) o venció la espera.
        for (const auto &held : nameWait_.release(std::chrono::steady_clock::now(), [this](const DropEvent &d) {
                 return !dns_.nameFor(DnsNames::normalize(d.remoteAddress), key(d.appPath)).empty();
             }))
            classify(held, cachedSigner(held.appPath), true);
        expireRules();
        if (std::chrono::steady_clock::now() >= nextRecheck) {
            recheckCoverage(++recheckRound_ % FullRecheckEvery == 0);
            nextRecheck = std::chrono::steady_clock::now() + CoverageRecheck;
        }
    }
}

void FirewallCore::recheckCoverage(bool full) {
    // Un archivo cubierto que cambió (reemplazado en una carpeta que el usuario puede escribir) se vuelve a verificar
    // y pierde el filtro si su firma ya no coincide con la regla. En la vuelta completa se verifica todo, aunque el
    // sello coincida. Sin mutex mientras se verifica: puede tardar.
    struct Seen {
        std::wstring path, ruleKey;
        FileStamp stamp;
    };
    std::vector<std::pair<std::wstring, Seen>> seen;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto &[k, c] : covered_)
            if (!c.filters.empty()) seen.push_back({k, {c.path, c.ruleKey, c.stamp}});
    }
    for (const auto &[k, s] : seen) {
        FileStamp stamp;
        const bool present = stampOf(s.path, stamp);
        if (present && !full && stamp == s.stamp) continue;
        const std::wstring signer = present ? signerOf(s.path) : std::wstring();
        std::lock_guard<std::mutex> lock(mutex_);
        const auto c = covered_.find(k);
        const auto rule = rules_.find(s.ruleKey);
        if (c == covered_.end() || c->second.ruleKey != s.ruleKey || rule == rules_.end()) continue;
        if (present && matches(rule->second, s.path, signer)) {
            c->second.stamp = stamp;
            continue;
        }
        std::wstring error;
        if (!wfp_.begin(error)) continue;
        for (auto id : c->second.filters) wfp_.removeFilter(id);
        if (!wfp_.commit(error)) {
            lastError_ = L"Could not withdraw a changed file from " + describe(rule->second) + L": " + error;
            continue;
        }
        addActivity({now(), s.path, present ? L"File changed: no longer covered by " + describe(rule->second)
                                            : L"File removed: no longer covered by " + describe(rule->second),
                     L"", 0, 0});
        covered_.erase(c);
        save(error);
    }
    // Lo mismo para los permisos de destino de reglas por firma que permiten.
    std::vector<std::pair<std::wstring, Seen>> grants;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto &[gk, g] : grants_) {
            const auto rule = rules_.find(g.ruleKey);
            if (!g.filters.empty() && g.action == Action::Allow && rule != rules_.end() && rule->second.scope != Scope::Path)
                grants.push_back({gk, {g.path, g.ruleKey, g.stamp}});
        }
    }
    for (const auto &[gk, s] : grants) {
        FileStamp stamp;
        const bool present = stampOf(s.path, stamp);
        if (present && !full && stamp == s.stamp) continue;
        const std::wstring signer = present ? signerOf(s.path) : std::wstring();
        std::lock_guard<std::mutex> lock(mutex_);
        const auto g = grants_.find(gk);
        const auto rule = rules_.find(s.ruleKey);
        if (g == grants_.end() || g->second.ruleKey != s.ruleKey || rule == rules_.end()) continue;
        if (present && matches(rule->second, s.path, signer)) {
            g->second.stamp = stamp;
            continue;
        }
        std::wstring error;
        if (!wfp_.begin(error)) continue;
        for (auto id : g->second.filters) wfp_.removeFilter(id);
        if (!wfp_.commit(error)) continue;
        addActivity({now(), s.path, L"File changed: destination permit withdrawn", g->second.address, 0, 0});
        grants_.erase(g);
        save(error);
    }
}

std::wstring FirewallCore::cachedSigner(const std::wstring &path) {
    WIN32_FILE_ATTRIBUTE_DATA info{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &info)) return {};
    const std::uint64_t size = (std::uint64_t(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    const auto k = key(path);
    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        const auto it = signers_.find(k);
        if (it != signers_.end() && it->second.size == size &&
            CompareFileTime(&it->second.written, &info.ftLastWriteTime) == 0)
            return it->second.signer;
    }
    // Un archivo que cambió (actualización en el lugar) se vuelve a verificar.
    const std::wstring signer = signerOf(path);
    std::lock_guard<std::mutex> lock(verifyMutex_);
    if (signers_.size() >= SignerCacheLimit) signers_.clear();
    signers_[k] = {info.ftLastWriteTime, size, signer};
    return signer;
}

void FirewallCore::classify(const DropEvent &drop, const std::wstring &cached, bool waited) {
    const auto k = key(drop.appPath);
    const auto t = fileTimeToUnix(drop.time);
    std::wstring signer = cached;
    bool perDestination = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto rule = rules_.find(k);
        if (rule != rules_.end() && !rule->second.filters.empty()) return;
        const auto cov = covered_.find(k);
        if (cov != covered_.end() && !cov->second.filters.empty()) return;
        // Modo por destino: la app no tiene regla entera propia y alguna regla por destino es de su identidad.
        if (rule == rules_.end()) destinationRuleFor(drop.appPath, cached, {}, {}, perDestination);
        // Una regla de ruta propia (sin filtro porque faltaba el exe al arrancar) manda: se pregunta, sin firma.
        if (!perDestination && (rule != rules_.end() || !signerRuleFor(drop.appPath, signer))) signer.clear();
    }
    if (perDestination) {
        classifyDestination(drop, cached, waited);
        return;
    }
    // Antes de dar un filtro por firma, la firma se verifica de nuevo sobre el archivo actual, sin caché.
    FileStamp stamp;
    const bool fresh = !signer.empty();
    if (fresh) signer = stampOf(drop.appPath, stamp) ? signerOf(drop.appPath) : std::wstring();
    std::lock_guard<std::mutex> lock(mutex_);
    const auto rule = rules_.find(k);
    if (rule != rules_.end() && !rule->second.filters.empty()) return;
    const auto cov = covered_.find(k);
    if (cov != covered_.end() && !cov->second.filters.empty()) return;
    const Rule *byPublisher = rule == rules_.end() && !signer.empty() ? signerRuleFor(drop.appPath, signer) : nullptr;
    // Sin verificación fresca, el aviso muestra la firma de la caché (no da permisos). Si la fresca falló, el aviso no
    // puede decir «valid signature» de un archivo que acaba de dejar de tenerla.
    if (!fresh) signer = cached;
    if (byPublisher) {
        std::wstring error;
        std::vector<std::uint64_t> ids;
        if (wfp_.begin(error)) {
            if (!wfp_.addAppFilter(drop.appPath, byPublisher->action, Direction::Outbound,
                                   weightFor(byPublisher->action), ids, error)) {
                wfp_.abort();
            } else if (wfp_.commit(error)) {
                Covered c{drop.appPath, ruleKey(*byPublisher), ids};
                c.stamp = stamp;
                covered_[k] = c;
                pending_.erase(k);
                addActivity({t, drop.appPath,
                             (byPublisher->action == Action::Allow ? L"Allowed by rule: " : L"Blocked by rule: ") +
                                 describe(*byPublisher) +
                                 (byPublisher->action == Action::Allow ? L" · next attempt connects" : L""),
                             drop.remoteAddress, drop.remotePort, drop.protocol});
                save(error);
                return;
            }
        }
        // Sin el filtro, la app no queda en el limbo: se pregunta como cualquier otra.
        lastError_ = L"Could not apply " + describe(*byPublisher) + L": " + error;
    }
    auto &p = pending_[k];
    if (p.attempts == 0) {
        if (pending_.size() > PendingLimit) {
            pending_.erase(k);
            return;
        }
        p.path = drop.appPath;
        p.first = t;
    }
    ++p.attempts;
    p.last = t;
    p.signer = signer;
    p.remoteAddress = drop.remoteAddress;
    p.remotePort = drop.remotePort;
    p.protocol = drop.protocol;
    p.host = dns_.nameFor(drop.remoteAddress, k);
    addActivity({t, p.path, L"Blocked · waiting for decision", drop.remoteAddress, drop.remotePort, drop.protocol});
}

void FirewallCore::classifyDestination(const DropEvent &drop, const std::wstring &cached, bool waited) {
    const auto k = key(drop.appPath);
    const auto t = fileTimeToUnix(drop.time);
    const std::wstring address = DnsNames::normalize(drop.remoteAddress);
    if (address.empty()) return;
    const std::wstring host = dns_.nameFor(address, k);
    // Un Allow por firma se verifica de nuevo sobre el archivo actual antes de abrir nada.
    bool needFresh = false, any = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const Rule *r = destinationRuleFor(drop.appPath, cached, host, address, any);
        needFresh = r && r->action == Action::Allow && r->scope != Scope::Path;
    }
    FileStamp stamp;
    std::wstring signer = cached;
    if (needFresh) signer = stampOf(drop.appPath, stamp) ? signerOf(drop.appPath) : std::wstring();
    std::lock_guard<std::mutex> lock(mutex_);
    const auto rule = rules_.find(k);
    if (rule != rules_.end() && !rule->second.filters.empty()) return;
    const Rule *r = destinationRuleFor(drop.appPath, signer, host, address, any);
    // Sin nombre todavía: Windows avisa la consulta DNS hasta un segundo después del intento. Preguntar ya crearía un
    // pedido que una regla por nombre resuelve un instante después (el aviso aparece y se cierra solo). Se espera el
    // nombre y recién ahí se decide; una regla por IP no lo necesita y se aplica ya.
    if (!r && any && host.empty() && !waited &&
        nameWait_.hold(drop, std::chrono::steady_clock::now()))
        return;
    // Una regla Allow por firma que apareció entre las dos miradas: el próximo intento la verifica.
    if (r && r->action == Action::Allow && r->scope != Scope::Path && !needFresh) return;
    if (r) {
        std::wstring error;
        bool added = false;
        if (grant(drop.appPath, address, *r, stamp, error, &added)) {
            pending_.erase(k + DestinationSeparator + address);
            addGrantActivity(t, drop.appPath, address, *r, drop.remoteAddress, drop.remotePort, drop.protocol);
            if (added) save(error);
            return;
        }
        lastError_ = L"Could not apply " + describe(*r) + L": " + error;
    }
    // Destino nuevo: un pendiente por dirección. Si la app ya no está en modo por destino (la regla se quitó en el
    // medio), pregunta por la app entera.
    const auto pk = any ? k + DestinationSeparator + address : k;
    if (any) pending_.erase(k); // un pedido viejo de la app entera ya no corresponde
    auto &p = pending_[pk];
    if (p.attempts == 0) {
        if (pending_.size() > PendingLimit) {
            pending_.erase(pk);
            return;
        }
        p.path = drop.appPath;
        p.first = t;
    }
    ++p.attempts;
    p.last = t;
    p.signer = needFresh ? signer : cached;
    // Normalizada: es parte del id del pedido en la ventana y no debe cambiar de formato entre intentos.
    p.remoteAddress = address;
    p.remotePort = drop.remotePort;
    p.protocol = drop.protocol;
    p.host = host;
    p.perDestination = any;
    addActivity({t, p.path, L"Blocked · waiting for decision", drop.remoteAddress, drop.remotePort, drop.protocol});
}

void FirewallCore::addGrantActivity(std::int64_t t, const std::wstring &path, const std::wstring &address,
                                    const Rule &rule, const std::wstring &remote, std::uint16_t port,
                                    std::uint8_t protocol) {
    // Lo que quedó de verdad: una IP compartida con un destino bloqueado sigue bloqueada.
    const auto g = grants_.find(key(path) + DestinationSeparator + address);
    const bool allowed = g != grants_.end() && g->second.action == Action::Allow;
    const auto owner = g != grants_.end() ? rules_.find(g->second.ruleKey) : rules_.end();
    addActivity({t, path,
                 (allowed ? L"Allowed by rule: " : L"Blocked by rule: ") +
                     describe(owner != rules_.end() ? owner->second : rule) +
                     (allowed ? L" · next attempt connects" : L""),
                 remote, port, protocol});
}

void FirewallCore::addActivity(Activity a) {
    activity_.push_back(std::move(a));
    while (activity_.size() > ActivityLimit) activity_.pop_front();
}

FirewallCore::Status FirewallCore::status() {
    std::lock_guard<std::mutex> lock(mutex_);
    Status s;
    s.ask = ask_;
    s.localNetwork = localNetwork_;
    s.names = dns_.stats();
    s.dynamic = options_.dynamic;
    s.allApps = options_.scope.empty();
    s.started = started_;
    s.pending = pending_.size();
    s.rules = rules_.size();
    s.lastError = lastError_;
    return s;
}

std::vector<Pending> FirewallCore::pending() {
    std::lock_guard<std::mutex> lock(mutex_);
    // Windows entrega la consulta DNS hasta un segundo después de que la app ya se conectó: el nombre que faltaba al
    // bloquear se completa acá, cuando la ventana vuelve a preguntar.
    for (auto &[k, p] : pending_)
        if (p.host.empty()) p.host = dns_.nameFor(p.remoteAddress, key(p.path));
    std::vector<Pending> out;
    for (const auto &[k, p] : pending_) out.push_back(p);
    return out;
}

std::vector<Rule> FirewallCore::rules() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Rule> out;
    for (const auto &[k, r] : rules_) out.push_back(r);
    return out;
}

std::vector<Covered> FirewallCore::covered() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Covered> out;
    for (const auto &[k, c] : covered_) out.push_back(c);
    return out;
}

std::vector<Grant> FirewallCore::grants() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Grant> out;
    for (const auto &[k, g] : grants_) out.push_back(g);
    return out;
}

std::vector<Activity> FirewallCore::activity() {
    std::lock_guard<std::mutex> lock(mutex_);
    return {activity_.begin(), activity_.end()};
}

void FirewallCore::load() {
    rules_.clear();
    covered_.clear();
    grants_.clear();
    destinationRules_ = 0;
    ask_ = true;
    localNetwork_ = true;
    lastError_.clear();
    if (options_.dataDir.empty()) return;
    std::ifstream in(options_.dataDir + L"\\rules.tsv", std::ios::binary);
    if (!in) return; // primera vez: sin reglas
    std::string line;
    int number = 0;
    std::wstring invalid;
    std::vector<Covered> coverage;
    std::vector<Grant> grantList;
    while (std::getline(in, line)) {
        ++number;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        const auto f = split(line);
        const auto action = [](const std::string &s) { return s == "allow" ? Action::Allow : Action::Block; };
        if (f[0] == "mode" && f.size() == 2) {
            ask_ = f[1] != "off";
        } else if (f[0] == "lan" && f.size() == 2) {
            localNetwork_ = f[1] != "ask";
        } else if (f[0] == "rule" && (f.size() == 5 || f.size() == 6) && (f[1] == "allow" || f[1] == "block")) {
            Rule r;
            r.action = action(f[1]);
            r.created = std::atoll(f[2].c_str());
            r.lastBlock = std::atoll(f[3].c_str());
            r.path = fromUtf8(f[4]);
            r.expires = f.size() == 6 ? std::atoll(f[5].c_str()) : 0;
            // Una temporal que venció con el motor apagado no se reinstala: esa app vuelve a preguntar.
            if (!r.path.empty() && (r.expires <= 0 || r.expires > now())) rules_[key(r.path)] = r;
        } else if (f[0] == "signer" && (f.size() == 7 || f.size() == 8) && (f[1] == "app" || f[1] == "publisher") &&
                   (f[2] == "allow" || f[2] == "block") && !f[5].empty() && (f[1] == "publisher" || !f[6].empty())) {
            Rule r;
            r.scope = f[1] == "app" ? Scope::App : Scope::Publisher;
            r.action = action(f[2]);
            r.created = std::atoll(f[3].c_str());
            r.lastBlock = std::atoll(f[4].c_str());
            r.signer = fromUtf8(f[5]);
            r.name = r.scope == Scope::App ? key(fromUtf8(f[6])) : std::wstring();
            r.expires = f.size() == 8 ? std::atoll(f[7].c_str()) : 0;
            if (r.expires <= 0 || r.expires > now()) rules_[ruleKey(r)] = r;
        } else if (f[0] == "covered" && f.size() == 3 && !f[1].empty() && !f[2].empty()) {
            coverage.push_back({fromUtf8(f[2]), key(fromUtf8(f[1])), {}});
        } else if (f[0] == "dest" && f.size() == 10 && (f[1] == "path" || f[1] == "app" || f[1] == "publisher") &&
                   (f[2] == "allow" || f[2] == "block") && !normalizeDestination(fromUtf8(f[8])).empty() &&
                   (f[1] == "path" ? !f[5].empty() : !f[6].empty() && (f[1] == "publisher" || !f[7].empty()))) {
            // dest <alcance> <acción> <creada> <último bloqueo> <ruta> <firmante> <nombre> <destino> <vencimiento>
            Rule r;
            r.scope = f[1] == "app" ? Scope::App : f[1] == "publisher" ? Scope::Publisher : Scope::Path;
            r.action = action(f[2]);
            r.created = std::atoll(f[3].c_str());
            r.lastBlock = std::atoll(f[4].c_str());
            r.path = r.scope == Scope::Path ? fromUtf8(f[5]) : std::wstring();
            r.signer = r.scope == Scope::Path ? std::wstring() : fromUtf8(f[6]);
            r.name = r.scope == Scope::App ? key(fromUtf8(f[7])) : std::wstring();
            r.destination = normalizeDestination(fromUtf8(f[8]));
            r.expires = std::atoll(f[9].c_str());
            if ((r.expires <= 0 || r.expires > now()) && !rules_.count(ruleKey(r))) {
                rules_[ruleKey(r)] = r;
                ++destinationRules_;
            }
        } else if (f[0] == "grant" && f.size() == 5 && !f[1].empty() && !f[2].empty() &&
                   !DnsNames::normalize(fromUtf8(f[3])).empty()) {
            // grant <clave de la regla> <ruta> <dirección> <último uso>
            Grant g;
            g.ruleKey = key(fromUtf8(f[1]));
            g.path = fromUtf8(f[2]);
            g.address = DnsNames::normalize(fromUtf8(f[3]));
            g.lastSeen = std::atoll(f[4].c_str());
            grantList.push_back(std::move(g));
        } else {
            // Una línea rota no deja al motor sin arrancar: eso dejaría la PC sin ninguna regla. Se saltea y se avisa.
            invalid += (invalid.empty() ? L"" : L", ") + std::to_wstring(number);
        }
    }
    // Después de leer todo: una cobertura puede aparecer antes que su regla.
    for (auto &c : coverage)
        if (rules_.count(c.ruleKey)) covered_[key(c.path)] = std::move(c);
    for (auto &g : grantList) {
        const auto rule = rules_.find(g.ruleKey);
        if (rule == rules_.end() || rule->second.destination.empty()) continue;
        g.action = rule->second.action;
        grants_[key(g.path) + DestinationSeparator + g.address] = std::move(g);
    }
    if (invalid.empty()) return;
    // La próxima decisión reescribe rules.tsv sin esas líneas: antes se guarda el original para no perderlas.
    in.close();
    const std::wstring target = options_.dataDir + L"\\rules.tsv";
    const bool kept = CopyFileW(target.c_str(), (target + L".bad").c_str(), FALSE);
    lastError_ = L"rules.tsv: skipped invalid lines " + invalid +
                 (kept ? L" (original kept as rules.tsv.bad)" : L" (could not keep a copy of the original)");
}

bool FirewallCore::save(std::wstring &error) {
    if (options_.dataDir.empty()) return true;
    std::ostringstream out;
    out << "# LGA GateBouncer rules v2\n";
    out << "mode\t" << (ask_ ? "ask" : "off") << "\n";
    out << "lan\t" << (localNetwork_ ? "allow" : "ask") << "\n";
    for (const auto &[k, r] : rules_) {
        // «Hasta reiniciar» no se guarda: el arranque siguiente ya no la encuentra. Las temporales llevan su vencimiento
        // como último campo; las permanentes quedan con el formato de siempre.
        if (r.expires == UntilRestart) continue;
        const char *action = r.action == Action::Allow ? "allow" : "block";
        const std::string expiry = r.expires > 0 ? "\t" + std::to_string(r.expires) : std::string();
        if (!r.destination.empty())
            out << "dest\t" << (r.scope == Scope::App ? "app" : r.scope == Scope::Publisher ? "publisher" : "path") << "\t"
                << action << "\t" << r.created << "\t" << r.lastBlock << "\t" << toUtf8(r.path) << "\t"
                << toUtf8(r.signer) << "\t" << toUtf8(r.name) << "\t" << toUtf8(r.destination) << "\t"
                << (r.expires > 0 ? r.expires : 0) << "\n";
        else if (r.scope == Scope::Path)
            out << "rule\t" << action << "\t" << r.created << "\t" << r.lastBlock << "\t" << toUtf8(r.path) << expiry
                << "\n";
        else
            out << "signer\t" << (r.scope == Scope::App ? "app" : "publisher") << "\t" << action << "\t" << r.created
                << "\t" << r.lastBlock << "\t" << toUtf8(r.signer) << "\t" << toUtf8(r.name) << expiry << "\n";
    }
    for (const auto &[k, c] : covered_) {
        const auto owner = rules_.find(c.ruleKey);
        if (owner != rules_.end() && owner->second.expires == UntilRestart) continue;
        out << "covered\t" << toUtf8(c.ruleKey) << "\t" << toUtf8(c.path) << "\n";
    }
    for (const auto &[k, g] : grants_) {
        const auto owner = rules_.find(g.ruleKey);
        if (owner == rules_.end() || owner->second.expires == UntilRestart) continue;
        out << "grant\t" << toUtf8(g.ruleKey) << "\t" << toUtf8(g.path) << "\t" << toUtf8(g.address) << "\t"
            << g.lastSeen << "\n";
    }
    const std::wstring target = options_.dataDir + L"\\rules.tsv";
    const std::wstring temp = target + L".tmp";
    {
        // Escrito y bajado a disco antes del reemplazo: un corte de luz no deja un rules.tsv vacío.
        HANDLE file = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        const auto text = out.str();
        DWORD written = 0;
        const bool ok = file != INVALID_HANDLE_VALUE && WriteFile(file, text.data(), DWORD(text.size()), &written, nullptr) &&
                        written == text.size() && FlushFileBuffers(file);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        if (!ok) {
            error = L"Could not write " + temp;
            lastError_ += (lastError_.empty() ? L"" : L"; ") + error;
            return false;
        }
    }
    if (!MoveFileExW(temp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        error = L"Could not replace " + target + L": " + WfpEngine::errorText(GetLastError());
        lastError_ += (lastError_.empty() ? L"" : L"; ") + error;
        return false;
    }
    return true;
}

} // namespace gbe
