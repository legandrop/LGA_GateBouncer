#pragma once
#include <QString>
#include <memory>
#include <optional>

namespace Gate::Lifecycle {
struct RunValue {
    bool exists = false;
    bool stringType = true;
    QString command;
    bool operator==(const RunValue &other) const {
        return exists == other.exists && stringType == other.stringType && command == other.command;
    }
};
enum class StartupState { Absent, Registered, ForeignValue, DeploymentRequired, Conflict, Error };
struct StartupResult {
    StartupState state = StartupState::Error;
    QString detail;
    bool succeeded() const { return state == StartupState::Absent || state == StartupState::Registered; }
};
class RunBackend {
  public:
    virtual ~RunBackend() = default;
    virtual bool read(RunValue &value, QString &error) = 0;
    // No es CAS atómico en el registro de Windows: relee antes y verifica después.
    virtual StartupResult replace(const RunValue &expected, const std::optional<QString> &command) = 0;
};
class DeploymentValidator {
  public:
    virtual ~DeploymentValidator() = default;
    virtual bool validate(const QString &executable, QString &reason) const = 0;
};
// Backend de GUI ordinary: una entrada exacta HKCU Run, sin servicios ni elevación.
std::unique_ptr<RunBackend> makeNativeRunBackend();
std::unique_ptr<DeploymentValidator> makeOrdinaryGuiDeploymentValidator();

class StartupPreference final {
  public:
    StartupPreference(QString executable, std::unique_ptr<RunBackend> backend,
                      std::unique_ptr<DeploymentValidator> validator);
    // Ninguna lectura ni inscripción ocurre en el constructor.
    StartupResult inspect();
    StartupResult setEnabled(bool enabled);
    QString command() const;
    static QString fixedCommand(const QString &executable);
  private:
    StartupResult classify(const RunValue &value) const;
    QString executable_;
    std::unique_ptr<RunBackend> backend_;
    std::unique_ptr<DeploymentValidator> validator_;
};
} // namespace Gate::Lifecycle
