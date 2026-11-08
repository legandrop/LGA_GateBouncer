#include "uiscale.h"
#include <QByteArray>
#include <QSettings>

namespace Gate::UiScale {
namespace {
int g_sessionLevel = 0;
bool g_envSet = false;
bool g_hadPrevious = false;
QByteArray g_previous;
constexpr char kEnvName[] = "QT_SCALE_FACTOR";
constexpr char kKey[] = "app/uiSize";
// El tamaño mínimo de la ventana (FirewallWindow): lo más chico que tiene que entrar en la pantalla.
constexpr QSize kWindow(900, 620);
QSettings store() { return QSettings(QSettings::NativeFormat, QSettings::UserScope, "LGA", "GateBouncer"); }
} // namespace

int clampLevel(int level) { return level >= 0 && level <= kMaxLevel ? level : kDefaultLevel; }

qreal factor(int level) {
    static constexpr qreal kFactors[kMaxLevel + 1] = {1.0, 1.1, 1.2};
    return kFactors[clampLevel(level)];
}

int percent(int level) { return qRound(factor(level) * 100); }

int maxFittingLevel(const QSize &area) {
    if (!area.isValid() || area.isEmpty()) return kMaxLevel;
    constexpr qreal kEpsilon = 1e-6;
    for (int level = kMaxLevel; level > 0; --level) {
        const qreal f = factor(level);
        if (kWindow.width() * f <= area.width() + kEpsilon && kWindow.height() * f <= area.height() + kEpsilon)
            return level;
    }
    return 0;
}

int readSavedLevel() {
    bool ok = false;
    const int level = store().value(kKey, kDefaultLevel).toInt(&ok);
    return ok ? clampLevel(level) : kDefaultLevel;
}

void saveLevel(int level) {
    auto s = store();
    s.setValue(kKey, clampLevel(level));
    s.sync();
}

void applyBeforeApp(int level) {
    g_sessionLevel = clampLevel(level);
    if (g_sessionLevel == 0) return;
    g_hadPrevious = qEnvironmentVariableIsSet(kEnvName);
    g_previous = qgetenv(kEnvName);
    qputenv(kEnvName, QByteArray::number(factor(g_sessionLevel), 'f', 2));
    g_envSet = true;
}

void clearEnvironmentAfterApp() {
    if (!g_envSet) return;
    if (g_hadPrevious) qputenv(kEnvName, g_previous);
    else qunsetenv(kEnvName);
    g_envSet = false;
}

int sessionLevel() { return g_sessionLevel; }

} // namespace Gate::UiScale
