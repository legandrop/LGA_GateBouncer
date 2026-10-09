#pragma once
#include "../common/pipe_ii_win.h"
#include "../common/review_open.h"
#include <atomic>
#include <thread>
namespace gb::controller {
struct OpenReference {
    wire::Id epoch{}, request{};
    std::uint64_t profile = 0;
};
class ReviewIngress {
  public:
    using Resolve = std::function<wire::Error(OpenReference)>;
    ReviewIngress(std::filesystem::path root, native::TokenEvidence identity, wire::Id epoch,
                  std::uint64_t profile, Resolve resolve);
    ~ReviewIngress();
    bool start();
    void stop();
    void requestStop() {
        if (stop_)
            SetEvent(stop_.value);
    }
    bool running() const { return running_; }

  private:
    bool peer(HANDLE pipe) const;
    void run();
    std::filesystem::path root_;
    native::TokenEvidence identity_;
    wire::Id helperEpoch_{}, epoch_{};
    std::uint64_t profile_;
    Resolve resolve_;
    native::Handle stop_{CreateEventW(nullptr, TRUE, FALSE, nullptr)}, anchor_;
    std::thread thread_;
    std::atomic<bool> running_{false};
};
} // namespace gb::controller
