#pragma once
#include "../common/wire_iv.h"
#include <algorithm>
#include <deque>

namespace gb::decisions {
// Sólo historia acotada: contexto copiado jamás acredita un lease OS.
class NativeActivityRing {
public:
    static constexpr std::size_t Limit = 256, ByteLimit = 256 * 1024;
    bool ready() const noexcept { return ready_ && !exhausted_; }
    std::uint64_t latest() const noexcept { return sequence_; }
    std::uint64_t gaps() const noexcept { return gapRevision_; }
    const wire::iv::ServiceContext &context() const noexcept { return context_; }
    std::uint64_t profile() const noexcept { return profile_; }
    static bool same(const wire::iv::ServiceContext &a, const wire::iv::ServiceContext &b) noexcept {
        return a.serviceEpoch == b.serviceEpoch && a.boot == b.boot &&
            a.engineContext == b.engineContext && a.engineBindingGeneration == b.engineBindingGeneration;
    }
    void fail() noexcept { ready_=false; exhausted_=true; clear(); }
    bool bind(const wire::iv::ServiceContext &context, std::uint64_t profile) noexcept {
      try {
        if (exhausted_ || wire::zero(context.serviceEpoch) || wire::zero(context.boot) ||
            wire::zero(context.engineContext) || !context.engineBindingGeneration || !profile) return false;
        if (ready() && same(context_, context) && profile_ == profile) return true;
        const bool prior = !wire::zero(context_.engineContext);
        clear(); context_ = context; profile_ = profile; ready_ = true;
        if (prior) {
            if (!advanceGap()) return false;
            auto event = gap(sequence_ + (sequence_ != UINT64_MAX), sequence_, 4, false);
            if (append(std::move(event)) != wire::Error::Ok) return false;
        }
        return ready();
      } catch (...) { fail(); return false; }
    }
    void lose(std::uint8_t reason = 1) noexcept {
      try {
        if (!ready()) return;
        clear();
        if (advanceGap() && sequence_ != UINT64_MAX) {
            auto event = gap(sequence_ + 1, sequence_, reason, false);
            append(std::move(event));
        }
        ready_ = false;
      } catch (...) { fail(); }
    }
    wire::Frame frame(wire::Type type) const {
        wire::Frame event; event.minor = 3; event.type = type;
        event.connection = context_.serviceEpoch; event.correlation = context_.serviceEpoch;
        wire::Bytes context;
        if (wire::iv::encodeServiceContext(context_, context) != wire::Error::Ok) return event;
        event.fields = {wire::value(wire::Tag::ServiceEpoch, context_.serviceEpoch),
            wire::value(wire::Tag::EventSeq, sequence_ == UINT64_MAX ? sequence_ : sequence_ + 1),
            wire::value(wire::Tag::SourceCoverage, 1, 1), wire::value(wire::Tag::ProfileGeneration, profile_),
            wire::value(wire::Tag::SourceEpoch, context_.engineContext),
            {wire::Tag::ServiceContext, true, std::move(context)}};
        return event;
    }
    wire::Error append(wire::Frame event) noexcept {
      try {
        if (!ready() || sequence_ == UINT64_MAX) { exhausted_ = true; ready_ = false; return wire::Error::Capacity; }
        for (auto &field : event.fields)
            if (field.tag == wire::Tag::EventSeq) field = wire::value(wire::Tag::EventSeq, sequence_ + 1);
        sort(event);
        wire::iv::ServiceContext actual;
        if (wire::iv::decodeServiceContext(event, actual) != wire::Error::Ok ||
            !same(actual, context_) || wire::get(event, wire::Tag::ProfileGeneration) != profile_)
            return wire::Error::Malformed;
        const auto charged = bytes(event);
        if (charged > ByteLimit) { lose(); return wire::Error::Capacity; }
        bool removed = false;
        while (!events_.empty() && (events_.size() >= Limit || charged > ByteLimit - charged_)) {
            lostThrough_ = wire::get(events_.front(), wire::Tag::EventSeq);
            charged_ -= bytes(events_.front()); events_.pop_front(); removed = true;
        }
        if (removed && !advanceGap()) return wire::Error::Capacity;
        events_.push_back(std::move(event)); ++sequence_; charged_ += charged;
        return wire::Error::Ok;
      } catch (...) { fail(); return wire::Error::Capacity; }
    }
    wire::Error after(std::uint64_t cursor, std::vector<wire::Frame> &out) const noexcept {
      try {
        out.clear();
        if (cursor > sequence_) return wire::Error::Stale;
        const auto first = events_.empty() ? sequence_ : wire::get(events_.front(), wire::Tag::EventSeq) - 1;
        if (cursor < first && cursor <= lostThrough_)
            out.push_back(gap(first, cursor, 3, true));
        for (const auto &event : events_) {
            if (wire::get(event, wire::Tag::EventSeq) > cursor) out.push_back(event);
            if (out.size() >= 16) break;
        }
        return wire::Error::Ok;
      } catch (...) { out.clear(); return wire::Error::Capacity; }
    }
    static void sort(wire::Frame &frame) {
        std::sort(frame.fields.begin(), frame.fields.end(), [](const auto &a, const auto &b) { return a.tag < b.tag; });
    }
    static std::size_t bytes(const wire::Frame &event) noexcept {
        std::size_t charged = wire::HeaderBytes + event.fields.capacity() * sizeof(wire::Field);
        for (const auto &field : event.fields) charged += 8 + field.bytes.capacity();
        return charged;
    }
private:
    void clear() noexcept { lostThrough_ = sequence_; events_.clear(); charged_ = 0; }
    bool advanceGap() noexcept {
        if (gapRevision_ == UINT64_MAX) { exhausted_ = true; ready_ = false; return false; }
        ++gapRevision_; return true;
    }
    wire::Frame gap(std::uint64_t cursor, std::uint64_t before, std::uint8_t reason, bool known) const {
        auto event = frame(wire::Type::ObservationGap);
        for (auto &field : event.fields)
            if (field.tag == wire::Tag::EventSeq) field = wire::value(wire::Tag::EventSeq, cursor);
        event.fields.insert(event.fields.end(), {wire::value(wire::Tag::Timestamp, 0),
            wire::value(wire::Tag::Presence, 0), wire::value(wire::Tag::Source, 3, 1),
            wire::value(wire::Tag::GapCount, gapRevision_), wire::value(wire::Tag::AfterEventSeq, before),
            wire::value(wire::Tag::LostCount, known ? cursor - before : 0),
            wire::value(wire::Tag::LostCountKnown, known, 1), wire::value(wire::Tag::GapReason, reason, 1)});
        sort(event); return event;
    }
    wire::iv::ServiceContext context_{};
    std::uint64_t profile_ = 0, sequence_ = 0, lostThrough_ = 0, gapRevision_ = 0;
    bool ready_ = false, exhausted_ = false;
    std::size_t charged_ = 0;
    std::deque<wire::Frame> events_;
};
}
