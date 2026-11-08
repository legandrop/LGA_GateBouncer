#pragma once
#include <QApplication>
namespace Gate {
bool initialize(QApplication &app);
QString embeddedFontFamily();
void applyPalette(QApplication &app);
} // namespace Gate
