#pragma once
#include <QPointer>
#include <QString>
#include <QWidget>
#include <functional>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QVBoxLayout;
class LgaColorPickerDialog;

namespace Gate {
class AccessToast;

// Editor de paletas, sólo para desarrollo (GATEBOUNCER_PALETTE_EDITOR=1): un color por grupo con el selector LGA, los
// tonos de cada grupo ajustables aparte, y guardar con nombre en la carpeta GATEBOUNCER_PALETTE_DIR (un .json por
// paleta). La ventana y el aviso cambian en vivo. El editor tiene colores fijos: una paleta ilegible no lo vuelve
// ilegible a él.
class PaletteEditor final : public QWidget {
  public:
    explicit PaletteEditor(const QString &folder, QWidget *parent = nullptr);
    ~PaletteEditor() override;
    static QString folderFromEnvironment();
    // Al cerrar el editor (la app de desarrollo se cierra con él, no queda en la bandeja).
    std::function<void()> onClosed;

  protected:
    void closeEvent(QCloseEvent *event) override;

  private:
    void buildRows();
    void refreshList(const QString &select = {});
    void loadIndex(int index);
    void save();
    void pick(const QString &roleId, const QString &memberHex); // memberHex vacío: el base del grupo
    void showSampleToast();
    void markDirty(bool dirty);

    QString folder_;
    QComboBox *list_ = nullptr;
    QLineEdit *name_ = nullptr;
    QCheckBox *liked_ = nullptr;
    QLabel *status_ = nullptr;
    QVBoxLayout *rows_ = nullptr;
    QPointer<LgaColorPickerDialog> picker_;
    QPointer<AccessToast> toast_;
    QList<QColor> recent_;
    bool loading_ = false;
};

} // namespace Gate
