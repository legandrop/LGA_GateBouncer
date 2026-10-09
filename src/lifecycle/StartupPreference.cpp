#include "StartupPreference.h"
#include <QDir>
#include <QRegularExpression>

namespace Gate::Lifecycle {
StartupPreference::StartupPreference(QString executable, std::unique_ptr<RunBackend> backend,
                                     std::unique_ptr<DeploymentValidator> validator)
    : executable_(std::move(executable)), backend_(std::move(backend)), validator_(std::move(validator)) {}
QString StartupPreference::fixedCommand(const QString &executable) {
    const QString path = QDir::toNativeSeparators(executable);
    // Sólo ruta local DOS absoluta. Ni URLs, UNC, device paths o argumentos libres.
    static const QRegularExpression absolute(QStringLiteral("^[A-Za-z]:[\\\\/].+\\.exe$"),
                                             QRegularExpression::CaseInsensitiveOption);
    if (!absolute.match(path).hasMatch() || path.mid(2).contains(':') || path.contains('"')) return {};
    for (QChar ch : path) if (ch.unicode() < 32 || ch.unicode() == 127) return {};
    for (QChar ch : QStringLiteral("<>|?*")) if (path.contains(ch)) return {};
    if (QDir::cleanPath(QDir::fromNativeSeparators(path)) != QDir::fromNativeSeparators(path)) return {};
    const QString command = QStringLiteral("\"%1\" --start-minimized").arg(path);
    // Run documenta una línea de comandos de hasta 260 caracteres.
    return command.size() <= 260 ? command : QString{};
}
QString StartupPreference::command() const { return fixedCommand(executable_); }
StartupResult StartupPreference::classify(const RunValue &value) const {
    if (!value.exists) return {StartupState::Absent, {}};
    if (command().isEmpty() || !value.stringType || value.command != command())
        return {StartupState::ForeignValue, QStringLiteral("The startup entry belongs to another command")};
    return {StartupState::Registered, QStringLiteral("Registered for user sign-in; Windows controls execution")};
}
StartupResult StartupPreference::inspect() {
    if (!backend_) return {StartupState::Error, QStringLiteral("Startup backend unavailable")};
    RunValue value;
    QString error;
    if (!backend_->read(value, error)) return {StartupState::Error, error};
    return classify(value);
}
StartupResult StartupPreference::setEnabled(bool enabled) {
    if (!backend_) return {StartupState::Error, QStringLiteral("Startup backend unavailable")};
    if (command().isEmpty()) return {StartupState::DeploymentRequired, QStringLiteral("A valid local executable path is required")};
    RunValue before;
    QString error;
    if (!backend_->read(before, error)) return {StartupState::Error, error};
    const auto current = classify(before);
    if (current.state == StartupState::ForeignValue) return current;
    if (!enabled && !before.exists) return current;
    if (enabled) {
        if (!validator_ || !validator_->validate(executable_, error))
            return {StartupState::DeploymentRequired, error.isEmpty() ? QStringLiteral("Deployment validation is required") : error};
        if (current.state == StartupState::Registered) return current;
    }
    return backend_->replace(before, enabled ? std::optional<QString>{command()} : std::nullopt);
}
} // namespace Gate::Lifecycle
