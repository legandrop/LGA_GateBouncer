#include "StartupPreference.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QGuiApplication>
#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace Gate::Lifecycle {
namespace {
#ifdef Q_OS_WIN
constexpr wchar_t runKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t valueName[] = L"LGA_GateBouncer";
QString registryError(LONG code) {
    return QStringLiteral("Startup registry operation failed (%1)").arg(code);
}
bool isolatedRun() {
    const QString platform = QGuiApplication::platformName().section(':', 0, 0);
    return platform == QStringLiteral("offscreen") || platform == QStringLiteral("minimal") ||
           !qEnvironmentVariableIsEmpty("LGA_HEADLESS_DESKTOP");
}
class NativeRunBackend final : public RunBackend {
  public:
    bool read(RunValue &value, QString &error) override {
        value = {};
        HKEY key = nullptr;
        LONG rc = RegOpenKeyExW(HKEY_CURRENT_USER, runKey, 0, KEY_QUERY_VALUE, &key);
        if (rc == ERROR_FILE_NOT_FOUND) return true;
        if (rc != ERROR_SUCCESS) { error = registryError(rc); return false; }
        DWORD type = 0, bytes = 0;
        rc = RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes);
        if (rc == ERROR_FILE_NOT_FOUND) { RegCloseKey(key); return true; }
        if (rc != ERROR_SUCCESS || bytes > 65536) {
            RegCloseKey(key); error = registryError(rc == ERROR_SUCCESS ? ERROR_INVALID_DATA : rc); return false;
        }
        value.exists = true;
        value.stringType = type == REG_SZ;
        if (!value.stringType) { RegCloseKey(key); return true; }
        std::wstring buffer(bytes / sizeof(wchar_t) + 1, L'\0');
        DWORD secondType = 0;
        rc = RegQueryValueExW(key, valueName, nullptr, &secondType,
                              reinterpret_cast<BYTE *>(buffer.data()), &bytes);
        RegCloseKey(key);
        if (rc != ERROR_SUCCESS) { error = registryError(rc); return false; }
        if (secondType != REG_SZ || bytes % sizeof(wchar_t) != 0 || bytes < sizeof(wchar_t)) {
            value.stringType = false; return true;
        }
        const size_t length = bytes / sizeof(wchar_t);
        // REG_SZ sin terminador o con NUL interno no puede acreditarse como propio.
        if (buffer[length - 1] != L'\0' || buffer.find(L'\0') != length - 1) {
            value.stringType = false; return true;
        }
        value.command = QString::fromWCharArray(buffer.data(), static_cast<qsizetype>(length - 1));
        return true;
    }
    StartupResult replace(const RunValue &expected, const std::optional<QString> &command) override {
        if (isolatedRun()) return {StartupState::Error, QStringLiteral("Native startup mutation is unavailable in isolated QA")};
        // Defensa además del dueño: el backend nativo sólo acepta el comando de ESTA GUI.
        const QString own = StartupPreference::fixedCommand(QCoreApplication::applicationFilePath());
        if (own.isEmpty() || (command && *command != own) ||
            (expected.exists && (!expected.stringType || expected.command != own)))
            return {StartupState::ForeignValue, QStringLiteral("Startup command ownership mismatch")};
        if (command) {
            QString reason;
            const auto validator = makeOrdinaryGuiDeploymentValidator();
            if (!validator->validate(QCoreApplication::applicationFilePath(), reason))
                return {StartupState::DeploymentRequired, reason};
        }
        RunValue current;
        QString error;
        if (!read(current, error)) return {StartupState::Error, error};
        if (!(current == expected)) return {StartupState::Conflict, QStringLiteral("Startup entry changed; refresh and retry")};
        HKEY key = nullptr;
        LONG rc = command ? RegCreateKeyExW(HKEY_CURRENT_USER, runKey, 0, nullptr, 0, KEY_SET_VALUE,
                                             nullptr, &key, nullptr)
                          : RegOpenKeyExW(HKEY_CURRENT_USER, runKey, 0, KEY_SET_VALUE, &key);
        if (!command && rc == ERROR_FILE_NOT_FOUND) return {StartupState::Absent, {}};
        if (rc != ERROR_SUCCESS) return {StartupState::Error, registryError(rc)};
        if (command) {
            const std::wstring text = command->toStdWString();
            rc = RegSetValueExW(key, valueName, 0, REG_SZ, reinterpret_cast<const BYTE *>(text.c_str()),
                                static_cast<DWORD>((text.size() + 1) * sizeof(wchar_t)));
        } else {
            rc = RegDeleteValueW(key, valueName);
            if (rc == ERROR_FILE_NOT_FOUND) rc = ERROR_SUCCESS;
        }
        RegCloseKey(key);
        if (rc != ERROR_SUCCESS) return {StartupState::Error, registryError(rc)};
        RunValue after;
        if (!read(after, error)) return {StartupState::Error, error};
        const RunValue desired{command.has_value(), true, command.value_or(QString{})};
        if (!(after == desired)) return {StartupState::Conflict, QStringLiteral("Startup entry changed during update")};
        return {command ? StartupState::Registered : StartupState::Absent, {}};
    }
};
class OrdinaryGuiDeploymentValidator final : public DeploymentValidator {
  public:
    bool validate(const QString &executable, QString &reason) const override {
        const QFileInfo file(executable);
        const QFileInfo current(QCoreApplication::applicationFilePath());
        if (StartupPreference::fixedCommand(executable).isEmpty() || !file.isFile() ||
            file.fileName().compare(QStringLiteral("GateBouncer.exe"), Qt::CaseInsensitive) != 0 ||
            file.canonicalFilePath().isEmpty() || file.canonicalFilePath() != current.canonicalFilePath()) {
            reason = QStringLiteral("Startup requires this local GateBouncer executable"); return false;
        }
        const std::wstring path = QDir::toNativeSeparators(file.absoluteFilePath()).toStdWString();
        const std::wstring drive = path.substr(0, 3);
        const UINT driveType = GetDriveTypeW(drive.c_str());
        if (driveType != DRIVE_FIXED && driveType != DRIVE_REMOVABLE) {
            reason = QStringLiteral("Startup requires an executable on a local drive"); return false;
        }
        const DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            reason = QStringLiteral("The executable identity cannot be validated"); return false;
        }
        // Carga sólo recursos; no ejecuta DllMain ni crea procesos/elevación.
        HMODULE image = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        if (!image) { reason = QStringLiteral("The executable manifest cannot be validated"); return false; }
        HRSRC resource = FindResourceW(image, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(24));
        bool ordinary = true;
        if (resource) {
            const DWORD size = SizeofResource(image, resource);
            HGLOBAL loaded = LoadResource(image, resource);
            const char *bytes = loaded ? static_cast<const char *>(LockResource(loaded)) : nullptr;
            if (!bytes || !size) ordinary = false;
            else {
                const QByteArray manifest(bytes, size);
                // Un manifiesto alternativo/desconocido requiere validación de despliegue.
                const QString xml = QString::fromUtf8(manifest);
                ordinary = !xml.contains(QStringLiteral("requireAdministrator"), Qt::CaseInsensitive) &&
                           !xml.contains(QStringLiteral("highestAvailable"), Qt::CaseInsensitive) &&
                           !manifest.contains('\0');
            }
        }
        FreeLibrary(image);
        if (!ordinary) reason = QStringLiteral("Startup supports an ordinary user GUI executable only");
        // No certifica ACL, integridad futura ni protección de un build escribible.
        return ordinary;
    }
};
#else
class NativeRunBackend final : public RunBackend {
  public:
    bool read(RunValue &, QString &error) override { error = QStringLiteral("Windows startup backend required"); return false; }
    StartupResult replace(const RunValue &, const std::optional<QString> &) override {
        return {StartupState::Error, QStringLiteral("Windows startup backend required")};
    }
};
class OrdinaryGuiDeploymentValidator final : public DeploymentValidator {
  public:
    bool validate(const QString &, QString &reason) const override {
        reason = QStringLiteral("Windows deployment required"); return false;
    }
};
#endif
} // namespace
std::unique_ptr<RunBackend> makeNativeRunBackend() { return std::make_unique<NativeRunBackend>(); }
std::unique_ptr<DeploymentValidator> makeOrdinaryGuiDeploymentValidator() {
    return std::make_unique<OrdinaryGuiDeploymentValidator>();
}
} // namespace Gate::Lifecycle
