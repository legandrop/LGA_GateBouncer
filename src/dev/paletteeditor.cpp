#include "dev/paletteeditor.h"

#include "accesstoast.h"
#include "customtooltip.h"
#include "explain/KnownApps.h"
#include "dev/LgaColorPickerDialog.h"
#include "palette.h"

#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPainter>
#include <QPushButton>
#include <QScreen>
#include <QScrollArea>
#include <QSettings>
#include <QStandardPaths>
#include <QUrl>
#include <QVBoxLayout>
#include <QWheelEvent>
#include <functional>

namespace Gate {

namespace {

// Colores fijos del editor (no pasan por la paleta).
const char *kEditorSheet = R"(
QWidget#paletteEditor { background: #141417; }
QWidget#paletteEditor QLabel { color: #C9C8CE; font-size: 12px; background: transparent; }
QLabel[r="head"] { color: #F0EEE8; font-size: 15px; font-weight: 700; }
QLabel[r="role"] { color: #E6E4DE; font-size: 13px; }
QLabel[r="hex"] { color: #8E8D95; font-size: 12px; font-family: 'Consolas'; }
QLabel[r="member"] { color: #A9A8AF; font-size: 12px; font-family: 'Consolas'; }
QLabel[r="status"] { color: #8E8D95; font-size: 12px; }
QLabel[r="status"][dirty="1"] { color: #F2CB3F; }
QFrame[r="row"] { background: #1C1C20; border: 1px solid #28282E; border-radius: 6px; }
QWidget#paletteEditor QPushButton { background: #2A2A31; border: 1px solid #3A3A43; border-radius: 5px; color: #E6E4DE;
    padding: 0 10px; min-height: 24px; font-size: 12px; }
QWidget#paletteEditor QPushButton:hover { background: #34343C; }
QWidget#paletteEditor QPushButton[k="flat"] { background: transparent; border: 0; color: #9D8FE0; padding: 0 4px; }
QWidget#paletteEditor QPushButton[k="flat"]:hover { background: transparent; color: #C5BBF4; }
QWidget#paletteEditor QLineEdit, QWidget#paletteEditor QComboBox { background: #101013; border: 1px solid #34343C;
    border-radius: 5px; color: #E6E4DE; padding: 0 8px; min-height: 24px; font-size: 12px; }
QWidget#paletteEditor QComboBox QAbstractItemView { background: #1C1C20; color: #E6E4DE; selection-background-color: #2E2A50; }
QWidget#paletteEditor QCheckBox { color: #E6E4DE; font-size: 12px; spacing: 6px; }
QWidget#paletteEditor QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid #55555F; border-radius: 3px;
    background: #101013; }
QWidget#paletteEditor QCheckBox::indicator:checked { background: #9D8FE0; border: 1px solid #C5BBF4; }
QScrollArea { border: 0; background: transparent; }
QScrollArea > QWidget > QWidget { background: transparent; }
QScrollBar:vertical { width: 8px; background: transparent; }
QScrollBar::handle:vertical { background: #3A3A43; border-radius: 3px; min-height: 24px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
)";

// La rueda no cambia el desplegable (regla de las apps LGA).
class NoWheelCombo final : public QComboBox {
  public:
    using QComboBox::QComboBox;

  protected:
    void wheelEvent(QWheelEvent *e) override { e->ignore(); }
};

// Muestra de color: pinta lo que devuelve «color» en cada repintado, así sigue a la paleta sin avisarle.
class Swatch final : public QWidget {
  public:
    Swatch(std::function<QColor()> color, QSize size, QWidget *parent = nullptr)
        : QWidget(parent), color_(std::move(color)) {
        setFixedSize(size);
        setCursor(Qt::PointingHandCursor);
        connect(Palette::Notifier::instance(), &Palette::Notifier::changed, this, qOverload<>(&QWidget::update));
    }
    std::function<void()> onClick;

  protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.setPen(QPen(QColor(underMouse() ? "#8E8D95" : "#45454E"), 1));
        p.setBrush(color_());
        p.drawRoundedRect(QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5), 4, 4);
    }
    void enterEvent(QEnterEvent *) override { update(); }
    void leaveEvent(QEvent *) override { update(); }
    void mouseReleaseEvent(QMouseEvent *e) override {
        if (e->button() == Qt::LeftButton && rect().contains(e->position().toPoint()) && onClick) onClick();
    }

  private:
    std::function<QColor()> color_;
};

QString upperHex(const QColor &c) { return c.name(QColor::HexRgb).toUpper(); }

QString slug(const QString &name) {
    QString s = name.normalized(QString::NormalizationForm_D).toLower();
    QString out;
    for (const QChar ch : s) {
        if (ch.category() == QChar::Mark_NonSpacing) continue;
        if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')) out += ch;
        else if (!out.endsWith('-')) out += '-';
    }
    while (out.endsWith('-')) out.chop(1);
    while (out.startsWith('-')) out.remove(0, 1);
    return out.isEmpty() ? QStringLiteral("paleta") : out;
}

QStringList membersOf(const QString &roleId) {
    if (roleId == QLatin1String("switch")) return Palette::switchMembers();
    const Palette::Role *r = Palette::role(roleId);
    return r ? r->members : QStringList();
}

// Clave aparte de la de la app (la de la app es un contrato con PipeSync): solo la usa el editor.
QSettings devStore() { return QSettings(QSettings::NativeFormat, QSettings::UserScope, "LGA", "GateBouncer_dev"); }

} // namespace

QString PaletteEditor::folderFromEnvironment() {
    const QString env = qEnvironmentVariable("GATEBOUNCER_PALETTE_DIR");
    if (!env.isEmpty()) return QDir::fromNativeSeparators(env);
    return QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + "/palettes";
}

PaletteEditor::PaletteEditor(const QString &folder, QWidget *parent) : QWidget(parent), folder_(folder) {
    setObjectName("paletteEditor");
    setWindowTitle("GateBouncer · Paletas (desarrollo)");
    setWindowFlags(Qt::Window | Qt::WindowStaysOnTopHint);
    setAttribute(Qt::WA_StyledBackground);
    setStyleSheet(kEditorSheet);
    QDir().mkpath(folder_);

    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(14, 12, 14, 12);
    root->setSpacing(8);
    auto *head = new QLabel("Paletas de color");
    head->setProperty("r", "head");
    root->addWidget(head);

    auto *pickRow = new QHBoxLayout;
    pickRow->setSpacing(6);
    list_ = new NoWheelCombo;
    list_->setMinimumWidth(220);
    pickRow->addWidget(new QLabel("Paleta"));
    pickRow->addWidget(list_, 1);
    auto *folderButton = new QPushButton("Carpeta");
    CustomTooltip::instance()->setToolTip(folderButton, "Abre la carpeta donde se guardan los .json");
    pickRow->addWidget(folderButton);
    root->addLayout(pickRow);

    auto *saveRow = new QHBoxLayout;
    saveRow->setSpacing(6);
    name_ = new QLineEdit;
    name_->setPlaceholderText("Nombre de la paleta");
    liked_ = new QCheckBox("Me gusta");
    auto *saveButton = new QPushButton("Guardar");
    CustomTooltip::instance()->setToolTip(saveButton, "Guarda con este nombre.\nUn nombre que ya existe se reemplaza.");
    saveRow->addWidget(new QLabel("Nombre"));
    saveRow->addWidget(name_, 1);
    saveRow->addWidget(liked_);
    saveRow->addWidget(saveButton);
    root->addLayout(saveRow);

    auto *toolRow = new QHBoxLayout;
    toolRow->setSpacing(6);
    status_ = new QLabel;
    status_->setProperty("r", "status");
    toolRow->addWidget(status_, 1);
    auto *revert = new QPushButton("Descartar cambios");
    auto *sample = new QPushButton("Aviso de ejemplo");
    CustomTooltip::instance()->setToolTip(sample, "Muestra un aviso de prueba para ver sus colores.\nNo decide nada.");
    toolRow->addWidget(revert);
    toolRow->addWidget(sample);
    root->addLayout(toolRow);

    auto *scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto *inner = new QWidget;
    rows_ = new QVBoxLayout(inner);
    rows_->setContentsMargins(0, 2, 4, 2);
    rows_->setSpacing(5);
    scroll->setWidget(inner);
    root->addWidget(scroll, 1);
    buildRows();

    connect(folderButton, &QPushButton::clicked, this, [this] { QDesktopServices::openUrl(QUrl::fromLocalFile(folder_)); });
    connect(saveButton, &QPushButton::clicked, this, &PaletteEditor::save);
    connect(name_, &QLineEdit::returnPressed, this, &PaletteEditor::save);
    connect(revert, &QPushButton::clicked, this, [this] { loadIndex(list_->currentIndex()); });
    connect(sample, &QPushButton::clicked, this, &PaletteEditor::showSampleToast);
    connect(list_, &QComboBox::activated, this, &PaletteEditor::loadIndex);
    connect(liked_, &QCheckBox::toggled, this, [this] {
        if (!loading_) markDirty(true);
    });
    connect(Palette::Notifier::instance(), &Palette::Notifier::changed, this, [this] {
        if (!loading_) markDirty(true);
    });

    refreshList(devStore().value("dev/palette").toString());
    loadIndex(list_->currentIndex());
    resize(470, 760);
    if (const QScreen *s = QGuiApplication::primaryScreen()) {
        const QRect a = s->availableGeometry();
        move(a.right() - width() - 24, a.top() + 40);
    }
}

PaletteEditor::~PaletteEditor() { delete toast_.data(); }

void PaletteEditor::closeEvent(QCloseEvent *event) {
    if (picker_) picker_->close();
    if (toast_) toast_->hide();
    QWidget::closeEvent(event);
    if (onClosed) onClosed();
}

void PaletteEditor::buildRows() {
    for (const auto &role : Palette::roles()) {
        const QString id = QString::fromLatin1(role.id);
        auto *row = new QFrame;
        row->setProperty("r", "row");
        auto *rl = new QVBoxLayout(row);
        rl->setContentsMargins(8, 6, 8, 6);
        rl->setSpacing(4);
        auto *line = new QHBoxLayout;
        line->setSpacing(8);
        auto *swatch = new Swatch([id] { return Palette::base(id); }, QSize(34, 22));
        swatch->onClick = [this, id] { pick(id, {}); };
        auto *label = new QLabel(QString::fromUtf8(role.label));
        label->setProperty("r", "role");
        label->setWordWrap(true);
        auto *hex = new QLabel;
        hex->setProperty("r", "hex");
        const auto updateHex = [hex, id] { hex->setText(upperHex(Palette::base(id))); };
        updateHex();
        connect(Palette::Notifier::instance(), &Palette::Notifier::changed, hex, updateHex);
        line->addWidget(swatch);
        line->addWidget(label, 1);
        line->addWidget(hex);
        rl->addLayout(line);

        const QStringList members = membersOf(id);
        if (members.size() > 1 || (members.size() == 1 && members.first().compare(role.base, Qt::CaseInsensitive) != 0)) {
            auto *toggle = new QPushButton(QString("Tonos (%1)").arg(members.size()));
            toggle->setProperty("k", "flat");
            toggle->setCursor(Qt::PointingHandCursor);
            line->addWidget(toggle);
            auto *box = new QWidget;
            auto *bl = new QVBoxLayout(box);
            bl->setContentsMargins(42, 2, 0, 2);
            bl->setSpacing(3);
            for (const QString &m : members) {
                auto *ml = new QHBoxLayout;
                ml->setSpacing(8);
                auto *ms = new Swatch([id, m] { return Palette::mapIn(id, m); }, QSize(26, 16));
                ms->onClick = [this, id, m] { pick(id, m); };
                auto *mt = new QLabel;
                mt->setProperty("r", "member");
                auto *reset = new QPushButton("Quitar ajuste");
                reset->setProperty("k", "flat");
                const QString key = id + '/' + m.toUpper();
                const auto update = [mt, reset, id, m, key] {
                    const bool fixed = Palette::current().overrides.contains(key);
                    mt->setText(QString("%1  →  %2%3").arg(m.toUpper(), upperHex(Palette::mapIn(id, m)),
                                                           fixed ? QStringLiteral("  (ajustado)") : QString()));
                    reset->setVisible(fixed);
                };
                update();
                connect(Palette::Notifier::instance(), &Palette::Notifier::changed, mt, update);
                connect(reset, &QPushButton::clicked, this, [id, m] { Palette::setOverride(id, m, QColor()); });
                ml->addWidget(ms);
                ml->addWidget(mt, 1);
                ml->addWidget(reset);
                bl->addLayout(ml);
            }
            box->hide();
            rl->addWidget(box);
            connect(toggle, &QPushButton::clicked, box, [box] { box->setVisible(!box->isVisible()); });
        }
        rows_->addWidget(row);
    }
    rows_->addStretch();
}

void PaletteEditor::refreshList(const QString &select) {
    list_->clear();
    list_->addItem(Palette::factory().name, QString());
    QDir dir(folder_);
    struct Entry {
        QString name, path;
        bool liked;
    };
    QList<Entry> entries;
    for (const QFileInfo &fi : dir.entryInfoList({"*.json"}, QDir::Files, QDir::Name)) {
        Palette::Data d;
        if (!Palette::load(fi.absoluteFilePath(), &d)) continue;
        entries.push_back({d.name.isEmpty() ? fi.completeBaseName() : d.name, fi.absoluteFilePath(), d.liked});
    }
    // Las que gustan primero.
    std::stable_sort(entries.begin(), entries.end(), [](const Entry &a, const Entry &b) { return a.liked && !b.liked; });
    for (const auto &e : entries) list_->addItem((e.liked ? QStringLiteral("★ ") : QString()) + e.name, e.path);
    const int i = select.isEmpty() ? 0 : list_->findData(select);
    list_->setCurrentIndex(qMax(0, i));
}

void PaletteEditor::loadIndex(int index) {
    const QString path = list_->itemData(index).toString();
    Palette::Data d = Palette::factory();
    if (!path.isEmpty()) {
        QString error;
        if (!Palette::load(path, &d, &error)) {
            status_->setText("No se pudo leer: " + error);
            return;
        }
        if (d.name.isEmpty()) d.name = QFileInfo(path).completeBaseName();
    }
    loading_ = true;
    Palette::apply(d);
    name_->setText(path.isEmpty() ? QString() : d.name);
    liked_->setChecked(d.liked);
    loading_ = false;
    devStore().setValue("dev/palette", path);
    status_->clear();
    markDirty(false);
}

void PaletteEditor::save() {
    const QString name = name_->text().trimmed();
    if (name.isEmpty()) {
        status_->setText("Poné un nombre para guardar.");
        name_->setFocus();
        return;
    }
    Palette::Data d = Palette::current();
    d.name = name;
    d.liked = liked_->isChecked();
    const QString path = QDir(folder_).filePath(slug(name) + ".json");
    QString error;
    if (!Palette::save(path, d, &error)) {
        status_->setText("No se pudo guardar: " + error);
        return;
    }
    loading_ = true;
    Palette::apply(d);
    loading_ = false;
    refreshList(path);
    devStore().setValue("dev/palette", path);
    markDirty(false);
    status_->setText("Guardada: " + QDir::toNativeSeparators(path));
}

void PaletteEditor::markDirty(bool dirty) {
    status_->setProperty("dirty", dirty ? "1" : "0");
    if (dirty) status_->setText("• Cambios sin guardar");
    else if (!status_->text().startsWith("Guardada")) status_->setText(list_->currentText());
    status_->style()->unpolish(status_);
    status_->style()->polish(status_);
}

void PaletteEditor::pick(const QString &roleId, const QString &memberHex) {
    if (picker_) picker_->close();
    const Palette::Role *role = Palette::role(roleId);
    if (!role) return;
    const bool member = !memberHex.isEmpty();
    const QColor initial = member ? Palette::mapIn(roleId, memberHex) : Palette::base(roleId);
    const QColor factory = member ? QColor(memberHex) : QColor(role->base);
    auto *dialog = new LgaColorPickerDialog(initial, factory, this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setModal(false);
    dialog->setWindowTitle(member ? QString("%1 · tono %2").arg(QString::fromUtf8(role->label), memberHex.toUpper())
                                  : QString::fromUtf8(role->label));
    // Presets: los colores base de la paleta actual, para emparejar grupos.
    QList<QColor> presets;
    for (const char *id : {"desk", "sheet", "card", "border", "title", "ink2", "accent", "ok"})
        presets << Palette::base(QString::fromLatin1(id));
    dialog->setPresetColors(presets);
    dialog->setRecentColors(recent_);
    connect(dialog, &LgaColorPickerDialog::colorChanged, this, [roleId, memberHex, member](const QColor &c) {
        // El reset del selector lleva el tono a su valor de fábrica: eso es quitar el ajuste, no fijarlo.
        if (member) Palette::setOverride(roleId, memberHex, c == QColor(memberHex) ? QColor() : c);
        else Palette::setBase(roleId, c);
    });
    connect(dialog, &QDialog::finished, this, [this, dialog](int) {
        const QColor c = dialog->selectedColor();
        recent_.removeAll(c);
        recent_.prepend(c);
        while (recent_.size() > 8) recent_.removeLast();
    });
    picker_ = dialog;
    dialog->show();
    dialog->move(geometry().left() - dialog->width() - 12, geometry().top() + 60);
}

void PaletteEditor::showSampleToast() {
    if (!toast_) {
        toast_ = new AccessToast;
        connect(toast_, &AccessToast::decided, toast_, &QWidget::hide);
        connect(toast_, &AccessToast::dismissed, toast_, &QWidget::hide);
    }
    AccessToast::Request r;
    r.id = "C:\\Windows\\System32\\curl.exe|93.184.216.34";
    r.perDestination = true;
    r.path = "C:\\Windows\\System32\\curl.exe";
    r.signer = "Microsoft Windows";
    r.attempts = 3;
    r.othersWaiting = 2;
    r.remote = "93.184.216.34";
    r.host = "example.com";
    r.port = 443;
    r.protocol = 6;
    r.known = KnownApps::hint(r.signer, r.path, r.host);
    r.launchedBy = "powershell.exe";
    toast_->setRequest(r);
    AccessToast::Explanation e;
    e.state = AccessToast::Explanation::Ready;
    e.what = "curl is a command-line tool that downloads files from the internet.";
    e.why = "A script ran it to fetch a page from example.com.";
    e.risk = "Low if you started the script yourself.";
    e.suggestion = "allow";
    e.reason = "Signed by Microsoft and in the Windows folder.";
    e.model = "sample";
    toast_->setExplanation(r.id, e);
    toast_->placeOn(screen());
    toast_->show();
    toast_->raise();
}

} // namespace Gate
