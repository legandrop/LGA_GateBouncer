#include "bootstrap.h"
#include <QFontDatabase>
#include <QFontInfo>
#include <QIcon>
#include <QPalette>

namespace Gate {
static QString family;
QString embeddedFontFamily() { return family; }
bool initialize(QApplication &app) {
    app.setApplicationName("LGA GateBouncer");
    app.setOrganizationName("LGA");
    app.setStyle("Fusion");
    for (const auto *name : {"Inter-Regular.ttf", "Inter-Medium.ttf", "Inter-SemiBold.ttf"}) {
        const int id = QFontDatabase::addApplicationFont(":/gatebouncer/resources/fonts/" +
                                                         QString::fromLatin1(name));
        if (id < 0 || QFontDatabase::applicationFontFamilies(id).isEmpty())
            return false;
        const QString loaded = QFontDatabase::applicationFontFamilies(id).first();
        if (family.isEmpty())
            family = loaded;
        if (family != loaded || !loaded.startsWith("Inter"))
            return false;
    }
    QFont font(family);
    font.setPixelSize(13);
    app.setFont(font);
    if (!QFontInfo(font).family().startsWith("Inter"))
        return false;
    app.setWindowIcon(QIcon(":/gatebouncer/resources/icons/LGA_GateBouncer.png"));
    QPalette palette;
    palette.setColor(QPalette::Window, QColor("#161616"));
    palette.setColor(QPalette::Base, QColor("#1d1d1d"));
    palette.setColor(QPalette::WindowText, QColor("#b2b2b2"));
    palette.setColor(QPalette::Text, QColor("#b2b2b2"));
    palette.setColor(QPalette::ButtonText, QColor("#b2b2b2"));
    palette.setColor(QPalette::Button, QColor("#2a2a2a"));
    palette.setColor(QPalette::Highlight, QColor("#393455"));
    palette.setColor(QPalette::HighlightedText, QColor("#e6e6e6"));
    app.setPalette(palette);
    app.setStyleSheet(R"(
        QWidget { color: #b2b2b2; font-family: 'Inter'; font-size: 13px; }
        QMainWindow, QWidget#root, QWidget#workspace, QWidget#page { background: #161616; }
        QLabel { background: transparent; }
        QLabel[role='muted'] { color: #8f8f8f; font-size: 12px; }
        QLabel[role='faint'] { color: #6f6f6f; font-size: 11px; }
        QLabel[role='strong'] { color: #ccc; font-weight: 500; }
        QLabel[role='title'] { color: #e6e6e6; font-size: 17px; font-weight: 600; }
        QLabel[role='heading'] { color: #ccc; font-size: 13px; font-weight: 600; }
        QLabel[role='warning'] { color: #d4a437; font-size: 11px; }
        QLabel[role='link'] { color: #c1b7d7; font-size: 11px; }
        QFrame#titlebar { background: #101010; border-bottom: 1px solid #262626; }
        QFrame#sidebar { background: #131313; border-right: 1px solid #262626; }
        QFrame[role='panel'] { background: #1d1d1d; border-radius: 6px; }
        QFrame[role='note'] { background: #1c1914; border: 1px solid #40351d; border-radius: 5px; }
        QFrame[role='neutral'] { background: #1c1a23; border: 1px solid #352e45; border-radius: 5px; }
        QPushButton { border: 0; border-radius: 4px; padding: 0 11px; background: #2a2a2a; font-size: 12px; font-weight: 500; min-height: 29px; }
        QPushButton:hover { background: #353535; color: #e6e6e6; }
        QPushButton:disabled { color: #656565; background: #212121; }
        QPushButton:focus, QLineEdit:focus, QComboBox:focus, QCheckBox:focus { border: 1px solid #774dcb; }
        QPushButton[role='primary'] { background: #443a91; color: #dddbee; }
        QPushButton[role='primary']:hover { background: #5145a3; }
        QPushButton[role='danger'] { background: #35211f; color: #e8836f; border: 1px solid #5c3330; }
        QPushButton[role='ghost'] { background: transparent; color: #8f8f8f; }
        QPushButton[role='ghost']:hover { background: #262626; }
        QPushButton[compact-close='true'] { padding: 0; }
        QPushButton[role='link'] { background: transparent; color: #9d8fe0; text-align: left; font-size: 11px; padding: 0; }
        QPushButton[role='nav'] { background: transparent; text-align: left; padding: 0 10px; min-height: 39px; font-size: 13px; font-weight: 400; }
        QPushButton[role='nav']:hover { background: #1b1b1b; }
        QPushButton[role='nav']:checked { background: #212027; color: #e6e6e6; }
        QLineEdit, QComboBox { background: #1a1a1a; border: 1px solid #2f2f2f; border-radius: 3px; color: #ccc; padding: 0 8px; min-height: 27px; font-size: 12px; }
        QComboBox { padding-right: 22px; }
        QComboBox::drop-down { border: 0; width: 20px; }
        QComboBox::down-arrow { image: none; }
        QComboBox QAbstractItemView { background: #1d1d1d; selection-background-color: #393455; border: 1px solid #39333f; }
        QCheckBox { spacing: 8px; font-size: 12px; }
        QCheckBox::indicator { width: 13px; height: 13px; border: 1px solid #514660; border-radius: 2px; background: #191919; }
        QCheckBox::indicator:checked { background: #774dcb; border: 1px solid #aa91dc; }
        QTableView { background: #1d1d1d; border: 0; border-radius: 6px; gridline-color: #242424; selection-background-color: #212027; outline: none; }
        QTableView:focus { border: 1px solid #4c4770; }
        QHeaderView::section { background: #191919; color: #8f8f8f; border: 0; border-bottom: 1px solid #262626; border-right: 1px solid #262626; height: 32px; padding-left: 11px; font-size: 11px; font-weight: 500; }
        QScrollArea { background: transparent; border: 0; }
        QScrollArea > QWidget > QWidget { background: transparent; }
        QScrollBar:vertical { width: 8px; background: #191919; margin: 0; }
        QScrollBar::handle:vertical { background: #3c3a41; border-radius: 3px; min-height: 25px; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
        QFrame#detail { background: #1c1c1c; border: 1px solid #39333f; border-radius: 6px; }
        QFrame#access-notice { background: #1d1d1d; border: 1px solid #49414f; border-radius: 8px; }
        QFrame#explanation { background: #191919; border: 1px solid #303030; border-radius: 5px; }
        QFrame#modal-overlay { background: rgba(0,0,0,164); }
        QFrame#modal-panel { background: #1e1e1e; border: 1px solid #3a3544; border-radius: 8px; }
        QFrame#message { background: #25212f; border: 1px solid #4b3e66; border-radius: 5px; }
        QProgressBar { border: 0; background: #292332; height: 3px; }
        QProgressBar::chunk { background: #c8b5e9; }
    )");
    return true;
}
} // namespace Gate
