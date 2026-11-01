#include "firewall_core.h"
#include <algorithm>
#include <cwctype>
#include <fstream>
#include <sstream>

namespace gbe {
namespace {

constexpr std::uint8_t WeightAsk = 1;
constexpr std::uint8_t WeightAllowRule = 10;
constexpr std::uint8_t WeightBlockRule = 15; // le gana también a los permisos de servicios de Windows
constexpr std::size_t ActivityLimit = 2000;
constexpr std::size_t PendingLimit = 500;

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

} // namespace

FirewallCore::FirewallCore(CoreOptions options) : options_(std::move(options)) {}

FirewallCore::~FirewallCore() { stop(); }

std::wstring FirewallCore::key(const std::wstring &path) {
    std::wstring k = path;
    std::transform(k.begin(), k.end(), k.begin(), [](wchar_t c) { return wchar_t(std::towlower(c)); });
    return k;
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
    if (!load(error)) return false;
    if (!wfp_.open(options_.dynamic, error) || !wfp_.ensureObjects(error)) return false;
    // Un arranque reconstruye todo desde las reglas guardadas en UNA transacción: si algo falla, quedan los filtros
    // anteriores tal cual y nunca un bloqueo general sin sus permisos de base.
    if (!wfp_.begin(error)) return false;
    bool ok = options_.dynamic || wfp_.removeAllOwnFilters(error);
    if (ok && options_.scope.empty()) ok = wfp_.addSystemAllowances(systemFilters_, error);
    std::size_t skipped = 0;
    for (auto &[k, rule] : rules_) {
        if (!ok) break;
        // Un ejecutable que ya no existe (desinstalado, actualizado, disco sin montar) no frena el arranque:
        // su regla queda guardada y, mientras falte, esa ruta vuelve a preguntar.
        const DWORD attributes = GetFileAttributesW(rule.path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
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
    if (ok && ask_) ok = applyAskFilters(error);
    if (!ok) {
        wfp_.abort();
        return false;
    }
    if (!wfp_.commit(error)) return false;
    if (skipped) lastError_ = std::to_wstring(skipped) + L" rules skipped: executable not found";
    if (!wfp_.subscribeDrops([this](const DropEvent &d) { onDrop(d); }, error)) return false;
    started_ = now();
    return true;
}

void FirewallCore::stop() {
    // Sin el mutex propio: cerrar la suscripción espera a que terminen los avisos en curso.
    wfp_.close();
    std::lock_guard<std::mutex> lock(mutex_);
    askFilters_.clear();
    systemFilters_.clear();
    for (auto &[k, rule] : rules_) rule.filters.clear();
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
    return wfp_.addAppFilter(rule.path, rule.action, Direction::Outbound,
                             rule.action == Action::Allow ? WeightAllowRule : WeightBlockRule, rule.filters, error);
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

bool FirewallCore::decide(const std::wstring &path, Action action, std::wstring &error) {
    if (path.empty() || path.find_first_of(L"\t\r\n") != std::wstring::npos) {
        error = L"Invalid application path";
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    const auto k = key(path);
    Rule rule;
    auto existing = rules_.find(k);
    if (existing != rules_.end()) rule = existing->second;
    rule.path = existing != rules_.end() ? existing->second.path : path;
    if (rule.action != action || existing == rules_.end()) rule.created = now();
    rule.action = action;
    // Regla nueva y retiro de la vieja en una sola transacción: nunca hay un hueco ni dos reglas.
    Rule fresh = rule;
    fresh.filters.clear();
    if (!wfp_.begin(error)) return false;
    if (!wfp_.addAppFilter(fresh.path, action, Direction::Outbound,
                           action == Action::Allow ? WeightAllowRule : WeightBlockRule, fresh.filters, error)) {
        wfp_.abort();
        return false;
    }
    for (auto id : rule.filters) wfp_.removeFilter(id);
    if (!wfp_.commit(error)) return false;
    rules_[k] = fresh;
    pending_.erase(k);
    addActivity({now(), fresh.path, action == Action::Allow ? L"Rule saved: Allow" : L"Rule saved: Block", L"", 0, 0});
    return save(error);
}

bool FirewallCore::removeRule(const std::wstring &path, std::wstring &error) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(key(path));
    if (it == rules_.end()) {
        error = L"No rule for this application";
        return false;
    }
    for (auto id : it->second.filters) wfp_.removeFilter(id);
    addActivity({now(), it->second.path, L"Rule removed", L"", 0, 0});
    rules_.erase(it);
    return save(error);
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
    if (std::find(askFilters_.begin(), askFilters_.end(), drop.filterId) == askFilters_.end()) return;
    // Carrera: la regla se guardó mientras el aviso viajaba. Una regla sin filtros es la que se omitió al arrancar
    // porque faltaba el ejecutable: su app volvió, así que se pregunta de nuevo y la decisión la reinstala.
    if (rule != rules_.end() && !rule->second.filters.empty()) return;
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
    p.remoteAddress = drop.remoteAddress;
    p.remotePort = drop.remotePort;
    p.protocol = drop.protocol;
    addActivity({t, p.path, L"Blocked · waiting for decision", drop.remoteAddress, drop.remotePort, drop.protocol});
}

void FirewallCore::addActivity(Activity a) {
    activity_.push_back(std::move(a));
    while (activity_.size() > ActivityLimit) activity_.pop_front();
}

FirewallCore::Status FirewallCore::status() {
    std::lock_guard<std::mutex> lock(mutex_);
    Status s;
    s.ask = ask_;
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

std::vector<Activity> FirewallCore::activity() {
    std::lock_guard<std::mutex> lock(mutex_);
    return {activity_.begin(), activity_.end()};
}

bool FirewallCore::load(std::wstring &error) {
    rules_.clear();
    ask_ = true;
    if (options_.dataDir.empty()) return true;
    std::ifstream in(options_.dataDir + L"\\rules.tsv", std::ios::binary);
    if (!in) return true; // primera vez: sin reglas
    std::string line;
    int number = 0;
    while (std::getline(in, line)) {
        ++number;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        const auto f = split(line);
        if (f[0] == "mode" && f.size() == 2) {
            ask_ = f[1] != "off";
        } else if (f[0] == "rule" && f.size() == 5 && (f[1] == "allow" || f[1] == "block")) {
            Rule r;
            r.action = f[1] == "allow" ? Action::Allow : Action::Block;
            r.created = std::atoll(f[2].c_str());
            r.lastBlock = std::atoll(f[3].c_str());
            r.path = fromUtf8(f[4]);
            if (!r.path.empty()) rules_[key(r.path)] = r;
        } else {
            error = L"rules.tsv: invalid line " + std::to_wstring(number);
            return false;
        }
    }
    return true;
}

bool FirewallCore::save(std::wstring &error) {
    if (options_.dataDir.empty()) return true;
    std::ostringstream out;
    out << "# LGA GateBouncer rules v1\n";
    out << "mode\t" << (ask_ ? "ask" : "off") << "\n";
    for (const auto &[k, r] : rules_)
        out << "rule\t" << (r.action == Action::Allow ? "allow" : "block") << "\t" << r.created << "\t" << r.lastBlock
            << "\t" << toUtf8(r.path) << "\n";
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
            lastError_ = error;
            return false;
        }
    }
    if (!MoveFileExW(temp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        error = L"Could not replace " + target + L": " + WfpEngine::errorText(GetLastError());
        lastError_ = error;
        return false;
    }
    return true;
}

} // namespace gbe
