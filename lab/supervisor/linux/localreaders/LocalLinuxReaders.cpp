#include "LocalLinuxReaders.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_addr.h>
#include <linux/magic.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

namespace gb::linuxlocal {
namespace {
constexpr int NoSlot = -1;
constexpr std::size_t MaximumFile = 1024 * 1024;
constexpr std::uint32_t WatchMask = IN_ATTRIB | IN_CREATE | IN_DELETE | IN_MOVED_FROM |
    IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF | IN_CLOSE_WRITE | IN_UNMOUNT;

bool Decimal(std::string_view text, std::uint64_t& output) {
    if (text.empty() || (text.size() > 1 && text.front() == '0')) return false;
    for (char ch : text) if (ch < '0' || ch > '9') return false;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), output);
    return result.ec == std::errc{} && result.ptr == text.data() + text.size();
}
bool SameIdentity(const struct stat& left, const struct stat& right, bool leaf) {
    if (left.st_dev != right.st_dev || left.st_ino != right.st_ino ||
        left.st_mode != right.st_mode || left.st_uid != right.st_uid || left.st_gid != right.st_gid)
        return false;
    return !leaf || (left.st_nlink == right.st_nlink && left.st_size == right.st_size &&
        left.st_mtim.tv_sec == right.st_mtim.tv_sec && left.st_mtim.tv_nsec == right.st_mtim.tv_nsec &&
        left.st_ctim.tv_sec == right.st_ctim.tv_sec && left.st_ctim.tv_nsec == right.st_ctim.tv_nsec);
}
bool BootId(const std::string& text) {
    if (text.size() != 37 || text.back() != '\n') return false;
    bool nonzero = false;
    for (std::size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (text[i] != '-') return false; }
        else {
            const char ch = text[i];
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
            nonzero = nonzero || ch != '0';
        }
    }
    return nonzero;
}
bool ProcessStart(const std::string& text, pid_t pid, std::uint64_t& start) {
    const auto opening = text.find(" (");
    const auto closing = text.rfind(')');
    std::uint64_t parsed = 0;
    if (opening == std::string::npos || closing == std::string::npos || closing <= opening ||
        !Decimal(std::string_view(text).substr(0, opening), parsed) ||
        parsed != static_cast<std::uint64_t>(pid) || closing + 2 >= text.size() || text[closing + 1] != ' ')
        return false;
    std::string_view rest(text.data() + closing + 2, text.size() - closing - 2);
    for (unsigned field = 3; field <= 22; ++field) {
        const auto separator = rest.find(' ');
        if (separator == std::string_view::npos || separator == 0) return false;
        const auto token = rest.substr(0, separator);
        if (field == 3 && (token.size() != 1 || std::string_view("RSDTtWKPI").find(token[0]) == std::string_view::npos))
            return false;
        if (field == 22) return Decimal(token, start) && start != 0;
        rest.remove_prefix(separator + 1);
    }
    return false;
}
int BaseDigit(char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    return ch == '+' ? 62 : ch == '/' ? 63 : -1;
}
bool DecodeBase64(std::string_view text, std::vector<unsigned char>& bytes) {
    if (text.empty() || text.size() > 512 || text.size() % 4) return false;
    for (std::size_t i = 0; i < text.size(); i += 4) {
        const int a = BaseDigit(text[i]), b = BaseDigit(text[i + 1]);
        const bool pad2 = text[i + 2] == '=', pad3 = text[i + 3] == '=';
        const int c = pad2 ? 0 : BaseDigit(text[i + 2]);
        const int d = pad3 ? 0 : BaseDigit(text[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0 || (pad2 && !pad3) ||
            ((pad2 || pad3) && i + 4 != text.size()) || (pad2 && (b & 15)) ||
            (pad3 && !pad2 && (c & 3))) return false;
        bytes.push_back(static_cast<unsigned char>((a << 2) | (b >> 4)));
        if (!pad2) bytes.push_back(static_cast<unsigned char>((b << 4) | (c >> 2)));
        if (!pad3) bytes.push_back(static_cast<unsigned char>((c << 6) | d));
    }
    return true;
}
bool SshString(const std::vector<unsigned char>& bytes, std::size_t& at, std::string_view expected) {
    if (at > bytes.size() || bytes.size() - at < 4) return false;
    std::uint32_t count = 0;
    for (unsigned i = 0; i < 4; ++i) count = (count << 8) | bytes[at++];
    if (count != expected.size() || count > bytes.size() - at ||
        std::memcmp(bytes.data() + at, expected.data(), count)) return false;
    at += count; return true;
}
bool PublicKey(const std::string& text, bool client) {
    if (text.empty() || text.size() > 2048 || text.back() != '\n' ||
        text.find('\n') != text.size() - 1 || text.find('\r') != std::string::npos) return false;
    const std::string_view algorithm = client ? "ecdsa-sha2-nistp256" : "ssh-ed25519";
    std::string_view line(text.data(), text.size() - 1);
    if (line.size() <= algorithm.size() + 1 || line.substr(0, algorithm.size()) != algorithm ||
        line[algorithm.size()] != ' ') return false;
    line.remove_prefix(algorithm.size() + 1);
    const auto separator = line.find(' ');
    if (client && separator != std::string_view::npos) return false;
    if (separator != std::string_view::npos) {
        const auto comment = line.substr(separator + 1);
        if (comment.empty()) return false;
        for (unsigned char ch : comment) if (ch < 32 || ch > 126) return false;
        line = line.substr(0, separator);
    }
    std::vector<unsigned char> bytes;
    if (!DecodeBase64(line, bytes)) return false;
    std::size_t at = 0;
    if (!SshString(bytes, at, algorithm)) return false;
    if (client && !SshString(bytes, at, "nistp256")) return false;
    if (bytes.size() - at < 4) return false;
    std::uint32_t count = 0;
    for (unsigned i = 0; i < 4; ++i) count = (count << 8) | bytes[at++];
    return count == (client ? 65u : 32u) && bytes.size() - at == count &&
        (!client || bytes[at] == 4);
}
std::int64_t Now() {
    timespec value{};
    if (clock_gettime(CLOCK_MONOTONIC, &value) || value.tv_sec < 0 ||
        value.tv_sec > (std::numeric_limits<std::int64_t>::max() - 1000) / 1000) return -1;
    return static_cast<std::int64_t>(value.tv_sec) * 1000 + value.tv_nsec / 1000000;
}
}

struct LocalLinuxReaders::Impl {
    struct Slot { int fd = -1; bool submitted = false; bool uncertain = false; };
    struct Node { int slot = NoSlot, parent = NoSlot; std::string name; struct stat identity{}; bool leaf = false; };
    struct Nic { int index = 0; std::string name; std::array<unsigned char, 6> mac{};
        std::array<unsigned char, 16> address{}; unsigned addressBytes = 0; };
    std::vector<Slot> slots;
    std::vector<Node> nodes;
    std::atomic<bool> cancelled{false};
    State state = State::Reserved;
    Cause cause = Cause::None;
    pid_t pid = 0;
    uid_t uid = 0, effective = 0, accountUid = 0;
    gid_t accountGid = 0;
    std::uint64_t start = 0;
    std::string boot, passwdBytes, authorizedBytes, hostBytes, namespaceName;
    int root = NoSlot, procPid = NoSlot, procNs = NoSlot, processStat = NoSlot, bootReader = NoSlot;
    int passwdReader = NoSlot, authorizedReader = NoSlot, hostReader = NoSlot;
    int pidSlot = NoSlot, notifySlot = NoSlot, netSlot = NoSlot, namespaceSlot = NoSlot;
    struct stat namespaceIdentity{};
    std::uint32_t port = 0;
    Nic nic;

    int Reserve() { slots.emplace_back(); return static_cast<int>(slots.size() - 1); }
    int Fd(int slot) const { return slot >= 0 ? slots[static_cast<std::size_t>(slot)].fd : -1; }
    int NodeFd(int node) const { return node >= 0 ? Fd(nodes[static_cast<std::size_t>(node)].slot) : -1; }
    void Fail(Cause why) { if (cause == Cause::None) cause = why; state = State::ClosePending; cancelled.store(true); }
    unsigned Count() const {
        unsigned count = 0;
        for (const auto& slot : slots) if (slot.fd >= 0 || slot.uncertain) ++count;
        return count;
    }
    Snapshot View() const { return {state, cause, Count()}; }
    bool Watch(int node) {
        const auto path = "/proc/" + std::to_string(pid) + "/fd/" + std::to_string(NodeFd(node));
        return inotify_add_watch(Fd(notifySlot), path.c_str(), WatchMask | IN_ONLYDIR) >= 0;
    }
    int OpenNode(int parent, const char* name, bool directory, bool watch = false) {
        if ((parent == NoSlot && std::strcmp(name, "/")) ||
            (parent != NoSlot && NodeFd(parent) < 0)) return NoSlot;
        const int slot = Reserve();
        const int flags = O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC | (directory ? O_DIRECTORY : 0);
        slots[static_cast<std::size_t>(slot)].fd = parent == NoSlot ? open(name, flags) : openat(NodeFd(parent), name, flags);
        if (Fd(slot) < 0) return NoSlot;
        Node node; node.slot = slot; node.parent = parent; node.name = name; node.leaf = !directory;
        if (fstat(Fd(slot), &node.identity) || (directory ? !S_ISDIR(node.identity.st_mode) :
            (!S_ISREG(node.identity.st_mode) || node.identity.st_nlink != 1 || node.identity.st_size < 0 ||
                static_cast<std::uint64_t>(node.identity.st_size) > MaximumFile))) return NoSlot;
        nodes.push_back(node);
        const int index = static_cast<int>(nodes.size() - 1);
        return !watch || Watch(index) ? index : NoSlot;
    }
    bool Trusted(int node, uid_t owner, gid_t group, mode_t exact = 0) const {
        if (node < 0) return false;
        const auto& info = nodes[static_cast<std::size_t>(node)].identity;
        return info.st_uid == owner && info.st_gid == group && !(info.st_mode & (S_IWGRP | S_IWOTH)) &&
            (!exact || (info.st_mode & 07777) == exact);
    }
    bool Paths() const {
        if (cancelled.load()) return false;
        for (const auto& node : nodes) {
            struct stat byFd{}, live{};
            if (fstat(Fd(node.slot), &byFd) || !SameIdentity(node.identity, byFd, node.leaf)) return false;
            const int parent = node.parent == NoSlot ? AT_FDCWD : NodeFd(node.parent);
            if (fstatat(parent, node.name.c_str(), &live, AT_SYMLINK_NOFOLLOW) ||
                !SameIdentity(node.identity, live, node.leaf)) return false;
        }
        return !cancelled.load();
    }
    bool Read(int node, std::size_t maximum, std::string& output) const {
        if (!Paths() || node < 0 || lseek(NodeFd(node), 0, SEEK_SET) != 0) return false;
        std::string candidate;
        std::array<char, 4096> buffer{};
        while (candidate.size() <= maximum) {
            const auto done = read(NodeFd(node), buffer.data(), std::min(buffer.size(), maximum + 1 - candidate.size()));
            if (done < 0) return false;
            if (done == 0) break;
            candidate.append(buffer.data(), static_cast<std::size_t>(done));
            if (candidate.size() > maximum || cancelled.load()) return false;
        }
        if (candidate.empty() || !Paths()) return false;
        output = std::move(candidate); return true;
    }
    bool Notifications() const {
        std::array<unsigned char, 4096> bytes{};
        const auto result = read(Fd(notifySlot), bytes.data(), bytes.size());
        if (result >= 0 || errno != EAGAIN) return false;
        const auto peek = recv(Fd(netSlot), bytes.data(), bytes.size(), MSG_PEEK | MSG_DONTWAIT);
        return peek < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
    }
    bool Namespace() const {
        if (!Paths()) return false;
        struct stat original{}, current{};
        std::array<char, 64> link{};
        const auto count = readlinkat(NodeFd(procNs), "net", link.data(), link.size());
        return count > 0 && static_cast<std::size_t>(count) < link.size() &&
            std::string(link.data(), static_cast<std::size_t>(count)) == namespaceName &&
            !fstat(Fd(namespaceSlot), &original) && SameIdentity(namespaceIdentity, original, false) &&
            !fstatat(NodeFd(procNs), "net", &current, 0) && SameIdentity(namespaceIdentity, current, false);
    }
    bool Process() const {
        if (getpid() != pid || getuid() != uid || geteuid() != effective || !Namespace()) return false;
        pollfd process{Fd(pidSlot), POLLIN, 0};
        if (poll(&process, 1, 0) != 0 || process.revents) return false;
        std::string statBytes, bootBytes;
        std::uint64_t observed = 0;
        return Read(processStat, 4096, statBytes) && ProcessStart(statBytes, pid, observed) && observed == start &&
            Read(bootReader, 64, bootBytes) && bootBytes == boot;
    }
    bool Account(const std::string& bytes) {
        if (bytes.empty() || bytes.back() != '\n' || bytes.find('\0') != std::string::npos ||
            bytes.find('\r') != std::string::npos) return false;
        unsigned matches = 0;
        std::vector<std::uint64_t> users;
        std::size_t at = 0;
        while (at < bytes.size()) {
            const auto end = bytes.find('\n', at);
            if (end == std::string::npos || end == at) return false;
            std::string_view line(bytes.data() + at, end - at);
            std::array<std::string_view, 7> fields{};
            for (unsigned field = 0; field < 6; ++field) {
                const auto colon = line.find(':');
                if (colon == std::string_view::npos) return false;
                fields[field] = line.substr(0, colon); line.remove_prefix(colon + 1);
            }
            fields[6] = line;
            if (line.find(':') != std::string_view::npos) return false;
            std::uint64_t user = 0, group = 0;
            if (!Decimal(fields[2], user) || !Decimal(fields[3], group) ||
                user > std::numeric_limits<uid_t>::max() || group > std::numeric_limits<gid_t>::max()) return false;
            users.push_back(user);
            if (fields[0] == "gatebouncerlab") {
                if (++matches != 1 || !user || !group || fields[1] != "x" ||
                    fields[5] != "/home/gatebouncerlab" || fields[6] != "/bin/bash") return false;
                accountUid = static_cast<uid_t>(user); accountGid = static_cast<gid_t>(group);
            }
            at = end + 1;
        }
        return matches == 1 && std::count(users.begin(), users.end(), accountUid) == 1;
    }
    bool AcquireFiles() {
        root = OpenNode(NoSlot, "/", true);
        if (root < 0) return false;
        const int proc = OpenNode(root, "proc", true);
        struct statfs fs{};
        if (proc < 0 || fstatfs(NodeFd(proc), &fs) || fs.f_type != PROC_SUPER_MAGIC) return false;
        // readlink del self generado por procfs comprueba el PID en ese montaje,
        // sin abrir el symlink ni afirmar namespace inicial o identidad de VM.
        std::array<char, 32> self{};
        const auto selfBytes = readlinkat(NodeFd(proc), "self", self.data(), self.size());
        if (selfBytes <= 0 || static_cast<std::size_t>(selfBytes) >= self.size() ||
            std::string(self.data(), static_cast<std::size_t>(selfBytes)) != std::to_string(pid)) return false;
        procPid = OpenNode(proc, std::to_string(pid).c_str(), true);
        if (procPid < 0) return false;
        processStat = OpenNode(procPid, "stat", false);
        procNs = OpenNode(procPid, "ns", true);
        if (procNs < 0 || processStat < 0) return false;
        namespaceSlot = Reserve();
        // Excepción cerrada: recurso ns/net del proc PID propio; no caller magicpath.
        slots[static_cast<std::size_t>(namespaceSlot)].fd = openat(NodeFd(procNs), "net", O_RDONLY | O_CLOEXEC);
        std::array<char, 64> link{};
        const auto count = readlinkat(NodeFd(procNs), "net", link.data(), link.size());
        if (Fd(namespaceSlot) < 0 || count <= 0 || static_cast<std::size_t>(count) >= link.size() ||
            fstat(Fd(namespaceSlot), &namespaceIdentity)) return false;
        namespaceName.assign(link.data(), static_cast<std::size_t>(count));
        std::uint64_t inode = 0;
        if (namespaceName.size() < 7 || namespaceName.substr(0, 5) != "net:[" || namespaceName.back() != ']' ||
            !Decimal(std::string_view(namespaceName).substr(5, namespaceName.size() - 6), inode) ||
            inode != namespaceIdentity.st_ino) return false;
        const int sys = OpenNode(proc, "sys", true);
        const int kernel = OpenNode(sys, "kernel", true);
        const int random = OpenNode(kernel, "random", true);
        if (sys < 0 || kernel < 0 || random < 0) return false;
        bootReader = OpenNode(random, "boot_id", false);
        std::string statBytes;
        if (!Read(processStat, 4096, statBytes) || !ProcessStart(statBytes, pid, start) ||
            !Read(bootReader, 64, boot) || !BootId(boot) || !Process()) return false;
        const int etc = OpenNode(root, "etc", true, true);
        const int ssh = OpenNode(etc, "ssh", true, true);
        if (!Trusted(etc, 0, 0) || !Trusted(ssh, 0, 0)) return false;
        passwdReader = OpenNode(etc, "passwd", false);
        hostReader = OpenNode(ssh, "ssh_host_ed25519_key.pub", false);
        if (!Trusted(passwdReader, 0, 0) || !Trusted(hostReader, 0, 0) ||
            !Read(passwdReader, MaximumFile, passwdBytes) || !Account(passwdBytes) ||
            !Read(hostReader, 2048, hostBytes) || !PublicKey(hostBytes, false)) return false;
        const int home = OpenNode(root, "home", true);
        const int account = OpenNode(home, "gatebouncerlab", true, true);
        const int keys = OpenNode(account, ".ssh", true, true);
        if (!Trusted(home, 0, 0) || !Trusted(account, accountUid, accountGid) ||
            !Trusted(keys, accountUid, accountGid, 0700)) return false;
        authorizedReader = OpenNode(keys, "authorized_keys", false);
        return Trusted(authorizedReader, accountUid, accountGid, 0600) &&
            Read(authorizedReader, 2048, authorizedBytes) && PublicKey(authorizedBytes, true) && Process();
    }
    template<class Callback> bool Attributes(const unsigned char* data, std::size_t bytes, Callback callback) {
        std::size_t at = 0;
        while (at < bytes) {
            if (bytes - at < sizeof(rtattr)) return false;
            rtattr attribute{}; std::memcpy(&attribute, data + at, sizeof(attribute));
            if (attribute.rta_len < sizeof(rtattr) || attribute.rta_len > bytes - at) return false;
            const auto step = static_cast<std::size_t>(RTA_ALIGN(attribute.rta_len));
            if (step > bytes - at || !callback(attribute.rta_type, data + at + sizeof(rtattr),
                static_cast<std::size_t>(attribute.rta_len) - sizeof(rtattr))) return false;
            at += step;
        }
        return at == bytes;
    }
    bool Link(const unsigned char* data, std::size_t bytes, unsigned& matches) {
        if (bytes < sizeof(ifinfomsg)) return false;
        ifinfomsg info{}; std::memcpy(&info, data, sizeof(info));
        if (info.ifi_index <= 0) return false;
        const auto startAt = static_cast<std::size_t>(NLMSG_ALIGN(sizeof(info)));
        if (startAt > bytes) return false;
        std::string name; std::array<unsigned char, 6> mac{};
        bool haveName = false, haveMac = false;
        if (!Attributes(data + startAt, bytes - startAt, [&](unsigned type, const unsigned char* value, std::size_t size) {
            if (type == IFLA_IFNAME) {
                if (haveName || size < 2 || size > IFNAMSIZ || value[size - 1] != 0) return false;
                for (std::size_t i = 0; i + 1 < size; ++i)
                    if (value[i] < 33 || value[i] > 126 || value[i] == '/' || value[i] == ':') return false;
                name.assign(reinterpret_cast<const char*>(value), size - 1); haveName = true;
            } else if (type == IFLA_ADDRESS && info.ifi_type == ARPHRD_ETHER) {
                if (haveMac || size != mac.size()) return false;
                std::memcpy(mac.data(), value, size); haveMac = true;
            }
            return true;
        })) return false;
        if (info.ifi_type != ARPHRD_ETHER || (info.ifi_flags & IFF_LOOPBACK) || !(info.ifi_flags & IFF_UP)) return true;
        if (!haveName || !haveMac || (mac[0] & 1) || std::all_of(mac.begin(), mac.end(), [](unsigned char b){ return b == 0; }) ||
            ++matches != 1) return false;
        nic.index = info.ifi_index; nic.name = std::move(name); nic.mac = mac; return true;
    }
    bool Address(const unsigned char* data, std::size_t bytes, unsigned& matches) {
        if (bytes < sizeof(ifaddrmsg)) return false;
        ifaddrmsg info{}; std::memcpy(&info, data, sizeof(info));
        const auto startAt = static_cast<std::size_t>(NLMSG_ALIGN(sizeof(info)));
        if (startAt > bytes) return false;
        if (info.ifa_index != static_cast<unsigned>(nic.index)) return true;
        const unsigned sizeExpected = info.ifa_family == AF_INET ? 4 : info.ifa_family == AF_INET6 ? 16 : 0;
        if (!sizeExpected) return false;
        std::array<unsigned char, 16> address{}, local{};
        bool haveAddress = false, haveLocal = false, haveFlags = false;
        std::uint32_t flags = info.ifa_flags;
        if (!Attributes(data + startAt, bytes - startAt, [&](unsigned type, const unsigned char* value, std::size_t size) {
            if (type == IFA_ADDRESS || type == IFA_LOCAL) {
                auto& have = type == IFA_ADDRESS ? haveAddress : haveLocal;
                auto& target = type == IFA_ADDRESS ? address : local;
                if (have || size != sizeExpected) return false;
                std::memcpy(target.data(), value, size); have = true;
            } else if (type == IFA_FLAGS) {
                if (haveFlags || size != sizeof(flags)) return false;
                std::memcpy(&flags, value, size); haveFlags = true;
                if ((flags & 255) != info.ifa_flags) return false;
            }
            return true;
        })) return false;
        if (info.ifa_scope != RT_SCOPE_UNIVERSE) return true;
        if ((!haveAddress && !haveLocal) || (haveAddress && haveLocal && address != local) ||
            (flags & (IFA_F_TENTATIVE | IFA_F_DEPRECATED | IFA_F_DADFAILED | IFA_F_SECONDARY))) return false;
        const auto& selected = haveLocal ? local : address;
        if (std::all_of(selected.begin(), selected.end(), [](unsigned char b){ return b == 0; }) ||
            (sizeExpected == 4 && (selected[0] == 127 || selected[0] >= 224)) ||
            (sizeExpected == 16 && (selected[0] == 255 || (selected[0] == 254 && (selected[1] & 192) == 128))) ||
            ++matches != 1) return false;
        nic.address = selected; nic.addressBytes = sizeExpected; return true;
    }
    bool Dump(bool links) {
        struct Request { nlmsghdr header; rtgenmsg body; } request{};
        const std::uint32_t sequence = links ? 1 : 2;
        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(rtgenmsg));
        request.header.nlmsg_type = links ? RTM_GETLINK : RTM_GETADDR;
        request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        request.header.nlmsg_seq = sequence; request.header.nlmsg_pid = port; request.body.rtgen_family = AF_UNSPEC;
        sockaddr_nl kernel{}; kernel.nl_family = AF_NETLINK;
        const auto beginning = Now();
        if (beginning < 0 || sendto(Fd(netSlot), &request, request.header.nlmsg_len, 0,
            reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)) != request.header.nlmsg_len) return false;
        unsigned matches = 0, messages = 0;
        std::array<unsigned char, 65536> buffer{};
        while (!cancelled.load()) {
            const auto now = Now();
            if (now < beginning || now - beginning >= 500) return false;
            pollfd ready{Fd(netSlot), POLLIN, 0};
            const int result = poll(&ready, 1, static_cast<int>(500 - (now - beginning)));
            if (result < 0 && errno == EINTR) continue;
            if (result != 1 || ready.revents != POLLIN) return false;
            sockaddr_nl sender{}; iovec vector{buffer.data(), buffer.size()};
            msghdr packet{}; packet.msg_name = &sender; packet.msg_namelen = sizeof(sender);
            packet.msg_iov = &vector; packet.msg_iovlen = 1;
            const auto received = recvmsg(Fd(netSlot), &packet, MSG_DONTWAIT);
            if (received <= 0 || packet.msg_flags & (MSG_TRUNC | MSG_CTRUNC) ||
                packet.msg_namelen != sizeof(sender) || sender.nl_family != AF_NETLINK || sender.nl_pid || sender.nl_groups)
                return false;
            const auto total = static_cast<std::size_t>(received);
            std::size_t at = 0;
            while (at < total) {
                if (total - at < sizeof(nlmsghdr) || ++messages > 1024) return false;
                nlmsghdr header{}; std::memcpy(&header, buffer.data() + at, sizeof(header));
                const auto aligned = static_cast<std::size_t>(NLMSG_ALIGN(header.nlmsg_len));
                if (header.nlmsg_len < NLMSG_HDRLEN || header.nlmsg_len > total - at || aligned > total - at ||
                    header.nlmsg_seq != sequence || header.nlmsg_pid != port || (header.nlmsg_flags & NLM_F_DUMP_INTR)) return false;
                const auto* payload = buffer.data() + at + NLMSG_HDRLEN;
                const auto bytes = static_cast<std::size_t>(header.nlmsg_len - NLMSG_HDRLEN);
                if (header.nlmsg_type == NLMSG_DONE) {
                    int error = 0;
                    if (bytes != 0 && bytes != sizeof(error)) return false;
                    if (bytes) std::memcpy(&error, payload, sizeof(error));
                    return !error && at + aligned == total && matches == 1;
                }
                if (header.nlmsg_type != (links ? RTM_NEWLINK : RTM_NEWADDR) || !(header.nlmsg_flags & NLM_F_MULTI) ||
                    !(links ? Link(payload, bytes, matches) : Address(payload, bytes, matches))) return false;
                at += aligned;
            }
        }
        return false;
    }
    bool AcquireNic() {
        netSlot = Reserve();
        slots[static_cast<std::size_t>(netSlot)].fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
        sockaddr_nl address{}; address.nl_family = AF_NETLINK;
        address.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
        if (Fd(netSlot) < 0 || bind(Fd(netSlot), reinterpret_cast<sockaddr*>(&address), sizeof(address))) return false;
        sockaddr_nl actual{}; socklen_t length = sizeof(actual);
        if (getsockname(Fd(netSlot), reinterpret_cast<sockaddr*>(&actual), &length) || length != sizeof(actual) ||
            actual.nl_family != AF_NETLINK || !actual.nl_pid || actual.nl_groups != address.nl_groups) return false;
        port = actual.nl_pid;
        return Dump(true) && Dump(false) && nic.index > 0 && nic.addressBytes && Notifications();
    }
    bool Current() {
        if (cancelled.load() || !Notifications() || !Paths() || !Process()) return false;
        std::string value;
        return Read(passwdReader, MaximumFile, value) && value == passwdBytes &&
            Read(authorizedReader, 2048, value) && value == authorizedBytes &&
            Read(hostReader, 2048, value) && value == hostBytes && Notifications() && Paths() && Process();
    }
    void Close() {
        cancelled.store(true); state = State::ClosePending;
        bool uncertain = false;
        for (auto it = slots.rbegin(); it != slots.rend(); ++it) {
            if (it->uncertain) { uncertain = true; continue; }
            if (it->fd < 0 || it->submitted) continue;
            it->submitted = true;
            const int original = it->fd;
            it->fd = -1;
            // Linux puede liberar fd aunque close falle: nunca reintentar el número.
            if (close(original)) { it->uncertain = true; uncertain = true; }
        }
        if (uncertain) cause = Cause::CloseUnconfirmed;
        else state = State::Closed;
    }
};

LocalLinuxReaders::LocalLinuxReaders() : own_(new Impl) {}
LocalLinuxReaders::~LocalLinuxReaders() noexcept { own_->Close(); }
std::unique_ptr<LocalLinuxReaders> LocalLinuxReaders::OpenLocalOwn() {
    auto reader = std::unique_ptr<LocalLinuxReaders>(new LocalLinuxReaders);
    auto& own = *reader->own_;
    own.pid = getpid(); own.uid = getuid(); own.effective = geteuid();
    try {
        own.pidSlot = own.Reserve();
        own.slots[static_cast<std::size_t>(own.pidSlot)].fd = static_cast<int>(syscall(SYS_pidfd_open, own.pid, 0));
        own.notifySlot = own.Reserve();
        own.slots[static_cast<std::size_t>(own.notifySlot)].fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (own.pid <= 0 || own.Fd(own.pidSlot) < 0) own.Fail(Cause::ProcessUnconfirmed);
        else if (own.Fd(own.notifySlot) < 0 || !own.AcquireFiles()) own.Fail(Cause::FilesystemUnconfirmed);
        else if (!own.AcquireNic()) own.Fail(Cause::NicUnconfirmed);
        else if (!own.Current()) own.Fail(Cause::ObservationChanged);
        else own.state = State::ObservedLocalReaders;
    } catch (...) { own.Fail(Cause::FilesystemUnconfirmed); }
    return reader;
}
LocalLinuxReaders::Snapshot LocalLinuxReaders::InspectLocalOwn() {
    if (own_->state == State::ObservedLocalReaders) {
        try { if (!own_->Current()) own_->Fail(Cause::ObservationChanged); }
        catch (...) { own_->Fail(Cause::ObservationChanged); }
    }
    return own_->View();
}
void LocalLinuxReaders::CancelLocalOwn() {
    own_->cancelled.store(true);
    if (own_->state != State::Closed) own_->state = State::ClosePending;
    if (own_->cause == Cause::None) own_->cause = Cause::Cancelled;
}
LocalLinuxReaders::Snapshot LocalLinuxReaders::CloseLocalOwn() {
    CancelLocalOwn(); own_->Close(); return own_->View();
}
int RunLocalLinuxReadOnlyEntry(int argumentCount) {
    if (argumentCount != 1) { std::fputs("Local reader: arguments rejected\n", stderr); return 2; }
    try {
        auto reader = LocalLinuxReaders::OpenLocalOwn();
        const auto observation = reader->InspectLocalOwn();
        const bool observed = observation.state == LocalLinuxReaders::State::ObservedLocalReaders;
        const auto terminal = reader->CloseLocalOwn();
        if (terminal.state != LocalLinuxReaders::State::Closed || terminal.ownedDescriptorCount) {
            std::fputs("Local reader: close unconfirmed\n", stderr); return 4;
        }
        if (!observed) { std::fputs("Local reader: observation unavailable\n", stderr); return 3; }
        std::printf("Local Linux readers: observed, retained descriptors %u, closed descriptors 0\n",
            observation.ownedDescriptorCount);
        return 0;
    } catch (...) { std::fputs("Local reader: resource failure\n", stderr); return 5; }
}
}
