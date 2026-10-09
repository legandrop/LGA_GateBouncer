#include "review_open.h"
#include <algorithm>
#include <map>
namespace gb::review {
using namespace wire;
namespace {
std::uint64_t n(const Bytes &b, std::size_t at, unsigned count) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < count; ++i)
        value |= std::uint64_t(b[at + i]) << (8 * i);
    return value;
}
void put(Bytes &b, std::uint64_t value, unsigned count) {
    auto bytes = integer(value, count);
    b.insert(b.end(), bytes.begin(), bytes.end());
}
} // namespace
Error validate(const Frame &f) {
    if (f.minor || zero(f.correlation) || !f.sequence || f.fields.size() > 8)
        return Error::Malformed;
    auto type = unsigned(f.type);
    std::map<Tag, std::size_t> schema;
    if (type == 1) {
        schema = {{Tag::ClientRole, 1}};
        if (!zero(f.connection) || f.sequence != 1 || get(f, Tag::ClientRole) != 1)
            return Error::Malformed;
    } else if (type == 2) {
        schema = {{Tag::ServiceEpoch, 16}, {Tag::Records, 16}, {Tag::ProfileGeneration, 8}};
        if (zero(f.connection) || f.sequence != 1 || zero(idValue(f, Tag::ServiceEpoch)) ||
            zero(idValue(f, Tag::Records)) || !get(f, Tag::ProfileGeneration))
            return Error::Malformed;
    } else if (type == 3) {
        schema = {{Tag::Records, 16}, {Tag::RequestId, 16}, {Tag::ProfileGeneration, 8}};
        if (zero(f.connection) || zero(idValue(f, Tag::Records)) ||
            zero(idValue(f, Tag::RequestId)) || !get(f, Tag::ProfileGeneration))
            return Error::Malformed;
    } else if (type == 4) {
        schema = {{Tag::ErrorCode, 2}};
        if (zero(f.connection) || get(f, Tag::ErrorCode) > 17)
            return Error::Malformed;
    } else
        return Error::Unsupported;
    if (f.fields.size() != schema.size())
        return Error::Malformed;
    std::size_t body = 0;
    for (auto &field : f.fields) {
        auto item = schema.find(field.tag);
        if (item == schema.end() || !field.required || field.bytes.size() != item->second)
            return Error::Malformed;
        body += 8 + field.bytes.size();
        schema.erase(item);
    }
    return body <= 448 ? Error::Ok : Error::Capacity;
}
Error encode(const Frame &f, Bytes &out) {
    auto error = gb::review::validate(f);
    if (error != Error::Ok)
        return error;
    Bytes body;
    for (auto &field : f.fields) {
        put(body, unsigned(field.tag), 2);
        put(body, 1, 2);
        put(body, field.bytes.size(), 4);
        body.insert(body.end(), field.bytes.begin(), field.bytes.end());
    }
    Bytes b = {'G', 'B', 'R', '1'};
    put(b, 1, 2);
    put(b, 0, 2);
    put(b, unsigned(f.type), 2);
    put(b, 0, 2);
    put(b, body.size(), 4);
    b.insert(b.end(), f.connection.begin(), f.connection.end());
    put(b, f.sequence, 8);
    b.insert(b.end(), f.correlation.begin(), f.correlation.end());
    put(b, 0, 8);
    b.insert(b.end(), body.begin(), body.end());
    out = std::move(b);
    return Error::Ok;
}
Error decode(const Bytes &b, Frame &out) {
    if (b.size() < 64 || b.size() > 512 || !std::equal(b.begin(), b.begin() + 4, "GBR1") ||
        n(b, 4, 2) != 1 || n(b, 6, 2) || n(b, 10, 2) || n(b, 56, 8) || n(b, 12, 4) != b.size() - 64)
        return Error::Malformed;
    Frame f;
    f.type = static_cast<Type>(n(b, 8, 2));
    std::copy_n(b.begin() + 16, 16, f.connection.begin());
    f.sequence = n(b, 32, 8);
    std::copy_n(b.begin() + 40, 16, f.correlation.begin());
    for (std::size_t at = 64; at < b.size();) {
        if (b.size() - at < 8 || f.fields.size() == 8)
            return Error::Malformed;
        auto tag = n(b, at, 2), flags = n(b, at + 2, 2), count = n(b, at + 4, 4);
        at += 8;
        if (flags != 1 || count > b.size() - at)
            return Error::Malformed;
        f.fields.push_back({static_cast<Tag>(tag), true,
                            Bytes(b.begin() + at, b.begin() + at + std::size_t(count))});
        at += std::size_t(count);
    }
    auto error = gb::review::validate(f);
    if (error == Error::Ok)
        out = std::move(f);
    return error;
}
} // namespace gb::review
