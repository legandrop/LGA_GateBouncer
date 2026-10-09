#pragma once
#include "../common/wire_v1.h"
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>

namespace gb {
using namespace wire;
constexpr std::size_t MaxRules=4096, MaxStoreBytes=16*1024*1024;
Id randomId();
Digest sha256(const Bytes& bytes);
struct Rule { Id id{},selector{}; std::uint8_t decision=1; Bytes appId; };
bool equalRules(const std::vector<Rule>& a,const std::vector<Rule>& b);
struct Snapshot {
    std::uint64_t desired=0,effective=0;
    bool effectiveKnown=false;
    State state=State::Applied;
    Id command{};
    Digest commandDigest{};
    std::vector<Rule> rules;
};
Bytes serializeSnapshot(const Snapshot& snapshot);
bool parseSnapshot(const Bytes& bytes,Snapshot& snapshot);
class PolicyStore {
public:
    explicit PolicyStore(std::filesystem::path root,bool fixture=false);
    virtual ~PolicyStore();
    PolicyStore(const PolicyStore&)=delete;
    PolicyStore& operator=(const PolicyStore&)=delete;
    virtual bool load(Snapshot& out,bool& exists);
    virtual bool save(const Snapshot& snapshot);
    const std::filesystem::path& root() const { return root_; }
private:
    bool prepareDirectory();
    std::filesystem::path root_;
    bool fixture_;
    std::vector<void*> directoryHandles_;
};
class SelectorRegistry {
public:
    // Sólo el backend registra APP_ID nativo; ningún mensaje lleva rutas/blobs.
    Id registerNative(const Bytes& appId);
    std::optional<Bytes> lookup(const Id& id) const;
private:
    mutable std::mutex mutex_;
    std::map<Id,Bytes> native_;
};
class Backend {
public:
    virtual ~Backend()=default;
    virtual bool available() const=0;
    virtual bool apply(const std::vector<Rule>& rules,std::uint64_t revision)=0;
    virtual bool matches(const std::vector<Rule>& rules,std::uint64_t revision)=0;
    virtual bool actualOs()const{return false;}
};
struct Status {
    std::uint64_t desired=0,effective=0,capabilities=ReadStatus;
    bool effectiveKnown=false;
    EngineState state=EngineState::Unavailable;
    BackendMode mode=BackendMode::WfpUsermode;
};
struct Outcome { State state=State::Failed; Error error=Error::Ok; Status status; };
class Coordinator {
public:
    Coordinator(PolicyStore& store,Backend& backend,SelectorRegistry& registry);
    bool initialize();
    Status status();
    Snapshot snapshot()const;
    Outcome mutate(const Frame& command,bool administrator);
private:
    Status statusUnlocked();
    PolicyStore& store_;Backend& backend_;SelectorRegistry& registry_;
    mutable std::mutex mutex_;
    Snapshot snapshot_;
    bool loaded_=false,recovery_=false;
};
}
