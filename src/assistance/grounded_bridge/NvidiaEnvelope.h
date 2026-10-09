#pragma once
#include <QByteArray>
#include <optional>
namespace Gate::Assistance::GroundedBridge {
std::optional<QByteArray> normalizeNvidiaEnvelope(const QByteArray &);
}
