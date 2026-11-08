// Banco de pruebas del idioma de las notas de lgaupdate (rev 5): `text_en` del JSON y
// `LgaWhatsNew::displayText()`.
//
// Sin red, sin archivos y sin ventanas: parsea JSON en memoria y mira que texto sale con el
// updater en ingles y en castellano. Se corre con el runner de QA de la Base, igual que el de
// reintentos (ver el README de esta carpeta). Sale con la cantidad de casos fallidos: 0 = todo bien.

#include "lgaupdate/LgaUpdateI18n.h"
#include "lgaupdate/LgaWhatsNew.h"

#include <QCoreApplication>
#include <QTextStream>

namespace {

int g_failures = 0;

void check(bool ok, const QString &name)
{
    QTextStream(stdout) << (ok ? "OK    " : "FALLA ") << name << Qt::endl;
    if (!ok) {
        ++g_failures;
    }
}

const QByteArray kBilingual = R"({"schemaVersion":1,"product":"legandrop/LGA_Test","name":"LGA Test",
 "versions":[
  {"version":"1.01","items":[
    {"kind":"improved","text":"Apps abre al instante.","text_en":"Apps opens instantly."},
    {"kind":"fixed","text":"El aviso ya no tapa la barra.","text_en":"  "}]},
  {"version":"1.00","items":[{"kind":"new","text":"Primera version."}]}]})";

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    const LgaWhatsNew::Notes notes = LgaWhatsNew::parse(kBilingual);
    check(notes.valid, QStringLiteral("parsea un JSON con text_en"));
    if (!notes.valid) {
        QTextStream(stdout) << notes.error << Qt::endl;
        return g_failures;
    }
    const auto first = notes.versions.at(0).items.at(0);
    const auto blank = notes.versions.at(0).items.at(1);
    const auto old = notes.versions.at(1).items.at(0);
    check(first.text == QStringLiteral("Apps abre al instante.")
              && first.textEn == QStringLiteral("Apps opens instantly."),
          QStringLiteral("guarda los dos textos"));
    check(blank.textEn.isEmpty() && old.textEn.isEmpty(),
          QStringLiteral("text_en vacio o ausente queda vacio"));

    LgaUpdateI18n::setLanguage(QStringLiteral("en"));
    const QList<LgaWhatsNew::VersionNotes> all = LgaWhatsNew::filtered(notes, QStringLiteral("win"));
    check(LgaWhatsNew::displayText(first) == first.textEn, QStringLiteral("en ingles: el ingles"));
    check(LgaWhatsNew::displayText(blank) == blank.text && LgaWhatsNew::displayText(old) == old.text,
          QStringLiteral("en ingles sin text_en: el castellano"));
    check(LgaWhatsNew::headline(all) == first.textEn, QStringLiteral("headline en ingles"));
    const QString htmlEn = LgaWhatsNew::toHtml(all);
    check(htmlEn.contains(QStringLiteral("Apps opens instantly."))
              && !htmlEn.contains(QStringLiteral("Apps abre al instante.")),
          QStringLiteral("toHtml en ingles"));

    LgaUpdateI18n::setLanguage(QStringLiteral("es"));
    check(LgaWhatsNew::displayText(first) == first.text, QStringLiteral("en castellano: el castellano"));
    const QString htmlEs = LgaWhatsNew::toHtml(all);
    check(htmlEs.contains(QStringLiteral("Apps abre al instante."))
              && !htmlEs.contains(QStringLiteral("Apps opens instantly.")),
          QStringLiteral("toHtml en castellano"));

    const QByteArray broken = R"({"schemaVersion":1,"versions":[{"version":"1.0","items":[
        {"kind":"new","text":"a","text_en":3}]}]})";
    check(!LgaWhatsNew::parse(broken).valid, QStringLiteral("text_en que no es texto invalida el JSON"));

    const QByteArray monolingual = R"({"schemaVersion":1,"versions":[{"version":"1.0","items":[
        {"kind":"new","text":"solo castellano"}]}]})";
    const LgaWhatsNew::Notes plain = LgaWhatsNew::parse(monolingual);
    LgaUpdateI18n::setLanguage(QStringLiteral("en"));
    check(plain.valid && LgaWhatsNew::displayText(plain.versions.at(0).items.at(0))
                             == QStringLiteral("solo castellano"),
          QStringLiteral("producto monolingue en ingles: sigue el castellano"));

    QTextStream(stdout) << (g_failures ? "FALLARON " : "TODO OK ") << g_failures << Qt::endl;
    return g_failures;
}
