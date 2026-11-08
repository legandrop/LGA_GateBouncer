#pragma once
#include <QHash>
#include <QString>

// Idioma de la interfaz, como en Mighty Tools: inglés (por defecto) o español.
//
// El texto en inglés del código ES la clave: I18n::tr("Allow") devuelve la traducción si el idioma elegido es español
// y la tabla la tiene; si no, el mismo texto en inglés (nunca vacío). La tabla vive en i18n_es.cpp y
// tools\qa\check_i18n.ps1 la confronta con el código.
//  - Con datos, el placeholder va adentro de la clave: I18n::tr("%1 attempts").arg(n).
//  - Nunca se arma una frase pegando traducciones sueltas: cada oración es una clave.
//  - Plurales: una clave por forma.
//  - El mismo texto con dos sentidos: I18n::trc("contexto", "texto") busca "contexto|texto".
// En español también se instala la traducción de Qt (qtbase_es.qm): menú contextual de los campos y botones estándar.
// Cambiar el idioma relanza la ventana (como el zoom): todo se vuelve a armar en el idioma nuevo.
namespace Gate::I18n {

enum class Language { English, Spanish };

Language language();
void setLanguage(Language language);

// "en" / "es": el valor guardado (app/language). Cualquier otro valor es inglés.
QString code(Language language);
Language fromCode(const QString &code);
// El nombre de cada idioma en su propio idioma, para el selector.
QString nativeName(Language language);

Language readSaved();
void save(Language language);

QString tr(const QString &english);
inline QString tr(const char *english) { return tr(QString::fromUtf8(english)); }
QString trc(const char *context, const char *english);

const QHash<QString, QString> &spanishTable();

} // namespace Gate::I18n
