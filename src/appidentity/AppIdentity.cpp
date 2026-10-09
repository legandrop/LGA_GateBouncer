#include "AppIdentity.h"

#include <algorithm>
#include <utility>

namespace gatebouncer::appidentity {
namespace {

bool validState(FieldState state) noexcept
{
    return state == FieldState::Missing || state == FieldState::Copied
        || state == FieldState::Unreadable;
}

bool coherent(const CopiedField& field) noexcept
{
    return validState(field.state)
        && (field.state == FieldState::Copied || field.bytes.empty());
}

bool validSidShape(const Bytes& sid) noexcept
{
    return sid.size() >= 8 && sid.size() <= MaximumSidBytes && sid[0] == 1
        && sid[1] <= 15 && sid.size() == 8u + 4u * sid[1];
}

bool high(char16_t c) noexcept { return c >= 0xd800 && c <= 0xdbff; }
bool low(char16_t c) noexcept { return c >= 0xdc00 && c <= 0xdfff; }

bool appText(const Bytes& bytes, std::u16string& text)
{
    if (bytes.empty() || (bytes.size() & 1u) != 0) return false;
    text.reserve(bytes.size() / 2);
    for (std::size_t i = 0; i < bytes.size(); i += 2) {
        const auto c = static_cast<char16_t>(bytes[i] | (std::uint16_t(bytes[i + 1]) << 8));
        if (c == 0) {
            if (i + 2 != bytes.size() || text.empty()) return false;
        } else {
            text.push_back(c);
        }
    }
    if (text.empty()) return false;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (high(text[i])) {
            if (i + 1 >= text.size() || !low(text[i + 1])) return false;
            ++i;
        } else if (low(text[i])) {
            return false;
        }
    }
    return true;
}

bool escaped(char16_t c) noexcept
{
    return c < 0x20 || (c >= 0x7f && c <= 0x9f) || c == 0x061c
        || (c >= 0x200b && c <= 0x200f) || (c >= 0x2028 && c <= 0x202e)
        || (c >= 0x2060 && c <= 0x206f) || c == 0xfeff
        || (c >= 0xfdd0 && c <= 0xfdef) || c == 0xfffe || c == 0xffff
        || c == u'&' || c == u'<' || c == u'>' || c == u'"' || c == u'\'';
}

std::u16string hexUnit(char16_t c)
{
    static constexpr char16_t digits[] = u"0123456789ABCDEF";
    std::u16string out = u"\\u0000";
    for (unsigned i = 0; i < 4; ++i) out[5 - i] = digits[(c >> (4 * i)) & 15];
    return out;
}

std::u16string safeText(const std::u16string& input, std::size_t limit)
{
    static constexpr char16_t mark[] = u"[truncated]";
    constexpr std::size_t markSize = 11;
    std::u16string out;
    out.reserve(std::min(limit, input.size()));
    std::vector<std::size_t> boundaries;
    boundaries.reserve(std::min(limit, input.size()));
    for (std::size_t i = 0; i < input.size(); ++i) {
        std::u16string atom;
        const auto c = input[i];
        if (high(c) && i + 1 < input.size() && low(input[i + 1])) {
            const auto codePoint = 0x10000u + ((std::uint32_t(c) - 0xd800u) << 10)
                + std::uint32_t(input[i + 1]) - 0xdc00u;
            if ((codePoint & 0xffffu) >= 0xfffeu) {
                atom = hexUnit(c) + hexUnit(input[i + 1]);
            } else {
                atom.push_back(c);
                atom.push_back(input[i + 1]);
            }
            ++i;
        } else if (high(c) || low(c) || escaped(c)) {
            atom = hexUnit(c);
        } else {
            atom.push_back(c);
        }
        // Retroceder por átomos sólo cuando hay truncado real, sin partir escapes.
        if (out.size() + atom.size() > limit) {
            while (out.size() + markSize > limit && !boundaries.empty()) {
                out.resize(boundaries.back());
                boundaries.pop_back();
            }
            out.append(mark);
            break;
        }
        boundaries.push_back(out.size());
        out.append(atom);
    }
    return out;
}

void length(Bytes& key, std::size_t size)
{
    const auto value = static_cast<std::uint32_t>(size);
    for (unsigned i = 0; i < 4; ++i) key.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
}

Bytes keyFor(const Target& target)
{
    Bytes key = {'G', 'B', 'A', 'I', 1,
        static_cast<std::uint8_t>(target.packageSid ? 1 : 0)};
    key.reserve(18 + target.appId.size() + target.userSid.size()
        + (target.packageSid ? target.packageSid->size() : 0));
    length(key, target.appId.size());
    length(key, target.userSid.size());
    length(key, target.packageSid ? target.packageSid->size() : 0);
    key.insert(key.end(), target.appId.begin(), target.appId.end());
    key.insert(key.end(), target.userSid.begin(), target.userSid.end());
    if (target.packageSid) key.insert(key.end(), target.packageSid->begin(), target.packageSid->end());
    return key;
}

Result rejected(EventBinding binding, Reason reason, State state = State::Unknown) noexcept
{
    Result result;
    result.binding = binding;
    result.reason = reason;
    result.state = state;
    return result;
}

} // namespace

Result attribute(const CopiedIdentity& input, SidFormatter& formatter) noexcept
{
    try {
        if (!input.binding.engineEpoch || !input.binding.eventSequence)
            return rejected(input.binding, Reason::InvalidBinding);
        for (const auto* field : {&input.appId, &input.userSid, &input.packageSid}) {
            if (!coherent(*field)) return rejected(input.binding, Reason::InconsistentField);
            if (field->state == FieldState::Unreadable)
                return rejected(input.binding, Reason::UnreadableField);
        }
        if (input.appId.state == FieldState::Missing)
            return rejected(input.binding, Reason::MissingAppId);
        if (input.userSid.state == FieldState::Missing)
            return rejected(input.binding, Reason::MissingUserSid);
        if (input.appId.bytes.size() > MaximumAppIdBytes
            || input.userSid.bytes.size() > MaximumSidBytes
            || input.packageSid.bytes.size() > MaximumSidBytes)
            return rejected(input.binding, Reason::Oversized);
        if (!validSidShape(input.userSid.bytes)
            || (input.packageSid.state == FieldState::Copied && !validSidShape(input.packageSid.bytes)))
            return rejected(input.binding, Reason::InvalidSid);

        std::u16string application;
        if (!appText(input.appId.bytes, application))
            return rejected(input.binding, Reason::InvalidAppId);
        std::u16string principal, package;
        if (!formatter.format(input.userSid.bytes, principal) || principal.empty()
            || principal.size() > MaximumPrincipalDisplayUnits)
            return rejected(input.binding, Reason::NativeFailure, State::Unavailable);
        const bool hasPackage = input.packageSid.state == FieldState::Copied;
        if (hasPackage && (!formatter.format(input.packageSid.bytes, package) || package.empty()
            || package.size() > MaximumPrincipalDisplayUnits))
            return rejected(input.binding, Reason::NativeFailure, State::Unavailable);

        Result result;
        result.binding = input.binding;
        result.display.appText = safeText(application, MaximumAppDisplayUnits);
        result.display.principalText = safeText(principal, MaximumPrincipalDisplayUnits);
        result.display.packageText = hasPackage
            ? safeText(package, MaximumPrincipalDisplayUnits) : u"Package restriction unspecified";
        result.display.scopeText = hasPackage
            ? u"Same application identity and principal, observed package; all instances and sessions. Shared hosts may include multiple services."
            : u"Same application identity and principal; all instances and sessions, without a package restriction. Shared hosts may include multiple services.";
        result.scope = Scope{hasPackage ? PackageScope::ExactObservedPackage : PackageScope::PackageUnspecified, true, true};
        Target target;
        target.appId = input.appId.bytes;
        target.userSid = input.userSid.bytes;
        if (hasPackage) target.packageSid = input.packageSid.bytes;
        target.opaqueKey = keyFor(target);
        result.target = std::move(target);
        result.state = State::Attributed;
        result.reason = Reason::None;
        return result;
    } catch (...) {
        return rejected(input.binding, Reason::NativeFailure, State::Unavailable);
    }
}

} // namespace gatebouncer::appidentity
