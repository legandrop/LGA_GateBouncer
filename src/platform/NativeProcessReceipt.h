#pragma once
#include "../data/contracts.h"
#include <memory>
#include <utility>
namespace gb::ipc::ii { class ReadPeerLease; }
namespace Gate {
class DecisionViewClient;
// Sólo el handler de respuesta autenticada sella este recibo; no existe factory de DTO/archivo.
class NativeProcessReceipt final {
    friend class DecisionViewClient;
    NativeProcessReceipt(Data::NativeSourceBinding binding,
        std::shared_ptr<const gb::ipc::ii::ReadPeerLease> peer, QString connection,
        QString descriptor, QString correlation, quint64 sequence, bool accepted,
        Data::NativeProcessFacts facts)
        : binding_(std::move(binding)), peer_(std::move(peer)), connection_(std::move(connection)),
          descriptor_(std::move(descriptor)), correlation_(std::move(correlation)), sequence_(sequence),
          accepted_(accepted), facts_(std::move(facts)) {}
    Data::NativeSourceBinding binding_;
    std::shared_ptr<const gb::ipc::ii::ReadPeerLease> peer_;
    QString connection_, descriptor_, correlation_;
    quint64 sequence_ = 0;
    bool accepted_ = false;
    Data::NativeProcessFacts facts_;
  public:
    const auto &binding() const { return binding_; }
    const auto &peer() const { return peer_; }
    const auto &connection() const { return connection_; }
    const auto &descriptor() const { return descriptor_; }
    const auto &correlation() const { return correlation_; }
    const auto &facts() const { return facts_; }
    quint64 sequence() const { return sequence_; }
    bool accepted() const { return accepted_; }
};
}