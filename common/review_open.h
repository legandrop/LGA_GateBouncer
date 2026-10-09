#pragma once
#include "wire_v1.h"
namespace gb::review {
// Namespace independiente GBR1, nunca decodifica decisión o selector.
wire::Error encode(const wire::Frame &frame, wire::Bytes &bytes);
wire::Error decode(const wire::Bytes &bytes, wire::Frame &frame);
wire::Error validate(const wire::Frame &frame);
} // namespace gb::review
