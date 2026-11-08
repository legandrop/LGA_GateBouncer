#include "i18n.h"
#include <QCoreApplication>
#include <QPointer>
#include <QSettings>
#include <QTranslator>
#include <QtDebug>
#include <atomic>

namespace Gate::I18n {
namespace {
// Atómico: también lo leen hilos que no son el de la interfaz (las explicaciones arman sus textos en el suyo).
std::atomic<Language> g_language{Language::English};

QSettings store() { return QSettings(QSettings::NativeFormat, QSettings::UserScope, "LGA", "GateBouncer"); }

void updateQtTranslator(Language language) {
    QCoreApplication *app = QCoreApplication::instance();
    if (!app) return;
    static QPointer<QTranslator> translator;
    if (language == Language::Spanish) {
        if (!translator) {
            auto *loaded = new QTranslator(app);
            if (!loaded->load(":/gatebouncer/resources/translations/qtbase_es.qm")) {
                qWarning() << "[I18n] No se pudo cargar qtbase_es.qm";
                delete loaded;
                return;
            }
            translator = loaded;
        }
        QCoreApplication::installTranslator(translator);
    } else if (translator) {
        QCoreApplication::removeTranslator(translator);
    }
}
} // namespace

Language language() { return g_language.load(); }

void setLanguage(Language language) {
    g_language.store(language);
    updateQtTranslator(language);
}

QString code(Language language) { return language == Language::Spanish ? "es" : "en"; }

Language fromCode(const QString &code) {
    return code.trimmed().compare(QLatin1String("es"), Qt::CaseInsensitive) == 0 ? Language::Spanish : Language::English;
}

QString nativeName(Language language) { return language == Language::Spanish ? QString::fromUtf8("Español") : "English"; }

Language readSaved() { return fromCode(store().value("app/language", "en").toString()); }

void save(Language language) {
    auto s = store();
    s.setValue("app/language", code(language));
    s.sync();
}

QString tr(const QString &english) {
    if (g_language.load() == Language::English) return english;
    const auto &table = spanishTable();
    const auto it = table.constFind(english);
    return it == table.constEnd() ? english : it.value();
}

QString trc(const char *context, const char *english) {
    const QString text = QString::fromUtf8(english);
    if (g_language.load() == Language::English) return text;
    const auto &table = spanishTable();
    const auto it = table.constFind(QString::fromUtf8(context) + QLatin1Char('|') + text);
    return it == table.constEnd() ? text : it.value();
}

} // namespace Gate::I18n
