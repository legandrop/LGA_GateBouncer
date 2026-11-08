#include "lgaupdate/LgaUpdateDialog.h"

#include <QAbstractButton>
#include <QMessageBox>
#include <QPushButton>

namespace LgaUpdateDialog {

int indexOf(const LgaUpdateDialogSpec &spec, LgaUpdateDialogSpec::Role role)
{
    for (int i = 0; i < spec.buttons.size(); ++i) {
        if (spec.buttons.at(i).role == role) {
            return i;
        }
    }
    return -1;
}

int presentFallback(QWidget *parent, const LgaUpdateDialogSpec &spec)
{
    QMessageBox box(parent);
    box.setWindowTitle(spec.title);
    box.setIcon(spec.warning ? QMessageBox::Warning : QMessageBox::Information);
    box.setTextFormat(Qt::RichText);
    QString text = spec.messageHtml;
    if (!spec.notesHtml.isEmpty()) {
        text += QStringLiteral("<hr>") + spec.notesHtml;
    }
    box.setText(text);
    if (!spec.details.isEmpty()) {
        box.setDetailedText(spec.details);
    }

    QList<QPushButton *> buttons;
    for (const LgaUpdateDialogSpec::Button &button : spec.buttons) {
        // ActionRole no reordena: los botones quedan en el orden de la spec.
        buttons.append(box.addButton(button.text, QMessageBox::ActionRole));
    }
    if (spec.defaultIndex >= 0 && spec.defaultIndex < buttons.size()) {
        box.setDefaultButton(buttons.at(spec.defaultIndex));
    }
    if (spec.escapeIndex >= 0 && spec.escapeIndex < buttons.size()) {
        box.setEscapeButton(buttons.at(spec.escapeIndex));
    }

    box.exec();
    const int clicked = buttons.indexOf(qobject_cast<QPushButton *>(box.clickedButton()));
    return clicked >= 0 ? clicked : spec.escapeIndex;
}

} // namespace LgaUpdateDialog
