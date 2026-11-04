#pragma once
// Bloqueos en modo por destino que esperan el nombre del servidor antes de preguntar.
//
// Windows entrega la consulta DNS (ETW, búfer que se vacía cada segundo) hasta un segundo después de que la app ya
// intentó conectarse. Sin el nombre, una regla por nombre («*.googleusercontent.com») no puede coincidir con el
// bloqueo: preguntar en ese momento crea un pedido falso que el DNS resuelve y borra un instante después, así que el
// aviso aparece y se cierra solo y Requests queda vacío. El bloqueo se guarda acá hasta que el nombre llega o vence la
// espera, y recién entonces se decide: permiso por regla, o pedido (ya con el nombre).
//
// Sin locks propios: la usa sólo el hilo de verificación del motor. Plantilla para probarla sin WFP.
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <deque>
#include <optional>
#include <utility>
#include <vector>

namespace gbe {

template <class Item> class NameWait {
  public:
    using Clock = std::chrono::steady_clock;

    NameWait(Clock::duration wait, std::size_t limit) : wait_(wait), limit_(limit) {}

    // Guarda el bloqueo hasta now + espera. false si está llena: ese bloqueo se decide ya, sin nombre.
    bool hold(Item item, Clock::time_point now) {
        if (held_.size() >= limit_) return false;
        held_.push_back({std::move(item), now + wait_});
        return true;
    }

    // Saca los que ya tienen nombre (named) o cuya espera venció, en el orden en que llegaron.
    template <class Named> std::vector<Item> release(Clock::time_point now, Named &&named) {
        std::vector<Item> out;
        for (auto it = held_.begin(); it != held_.end();) {
            if (now >= it->deadline || named(it->item)) {
                out.push_back(std::move(it->item));
                it = held_.erase(it);
            } else {
                ++it;
            }
        }
        return out;
    }

    // Cuándo vence la próxima espera: el hilo tiene que despertarse a esa hora aunque no llegue nada.
    std::optional<Clock::time_point> nextDeadline() const {
        if (held_.empty()) return std::nullopt;
        auto first = held_.front().deadline;
        for (const auto &h : held_) first = std::min(first, h.deadline);
        return first;
    }

    std::size_t size() const { return held_.size(); }

  private:
    struct Held {
        Item item;
        Clock::time_point deadline;
    };
    Clock::duration wait_;
    std::size_t limit_;
    std::deque<Held> held_;
};

} // namespace gbe
