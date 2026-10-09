#pragma once
#include "../common/protected_file_win.h"
#include <map>
namespace gb::controller {
// Inventory nativo cerrado, provisto por despliegue administrativo protegido.
using Inventory = std::map<std::wstring, wire::Digest>;
bool parseInventory(const wire::Bytes &bytes, Inventory &inventory);
class Deployment {
  public:
    explicit Deployment(std::filesystem::path root)
        : root_(std::move(root)), directory_(root_, true) {}
    bool verify(const std::filesystem::path &ownImage);
    bool prepareEnvironment();
    const std::filesystem::path &root() const { return root_; }

  private:
    bool readFile(const std::filesystem::path &relative, wire::Bytes &bytes, std::size_t cap);
    bool enumerate(const std::filesystem::path &relative, unsigned depth,
                   std::vector<std::wstring> &files);
    std::filesystem::path root_;
    native::ProtectedDirectory directory_;
    std::vector<native::Handle> held_;
    Inventory inventory_;
    bool verified_ = false;
};
} // namespace gb::controller
