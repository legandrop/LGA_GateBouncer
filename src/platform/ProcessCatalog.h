#pragma once
#include "../data/contracts.h"

namespace Gate::Data {
struct ProcessCatalogResult {
    QVector<ProcessObservation> processes;
    QString error;
    quint64 generation = 0;
};
class ProcessCatalog final {
  public:
    ProcessCatalog();
    ProcessCatalogResult refresh();
  private:
    QString epoch_;
    quint64 generation_ = 0;
};
} // namespace Gate::Data
