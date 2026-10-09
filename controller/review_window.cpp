#include "review_window.h"
#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QListWidget>
#include <QMouseEvent>
#include <QPushButton>
#include <QSignalBlocker>
#include <QVBoxLayout>

namespace gb::controller {
using namespace wire;
ReviewWindow::ReviewWindow(std::filesystem::path root, QWidget *parent,
                           std::unique_ptr<ipc::ii::SessionChannel> channel)
    : QWidget(parent), root_(std::move(root)), session_(this, std::move(channel)) {
    setWindowTitle("GateBouncer — Review decisions");
    setMinimumSize(640, 520);
    resize(780, 600);
    setStyleSheet(
        "QWidget{background:#17171b;color:#e8e8ec;font-size:13px} QLabel{background:transparent} "
        "QPushButton,QComboBox{background:#29292e;padding:9px;border:1px solid "
        "#45454c;border-radius:5px} QPushButton:disabled{color:#777780} "
        "QListWidget{background:#202024;border:1px solid #38383e;padding:6px}");
    auto layout = new QVBoxLayout(this);
    layout->setContentsMargins(24, 24, 24, 24);
    layout->setSpacing(12);
    state_ = new QLabel("Engine unavailable. No decision has been sent.", this);
    state_->setObjectName("reviewStateLabel");
    state_->setWordWrap(true);
    layout->addWidget(state_);
    auto notice = new QLabel(
        "Permanent path rules affect all users and instances. Engine coverage is unvalidated.",
        this);
    notice->setWordWrap(true);
    layout->addWidget(notice);
    queued_ = new QLabel("No queued references", this);
    layout->addWidget(queued_);
    rows_ = new QListWidget(this);
    rows_->setObjectName("reviewPendingList");
    layout->addWidget(rows_);
    auto row = new QHBoxLayout;
    connect_ = new QPushButton("Connect review session", this);
    connect_->setObjectName("reviewConnectButton");
    auto refresh = new QPushButton("Refresh pending", this);
    auto selectButton = new QPushButton("Review selected request", this);
    selectButton->setObjectName("reviewSelectButton");
    row->addWidget(connect_);
    row->addWidget(refresh);
    row->addWidget(selectButton);
    layout->addLayout(row);
    auto reconcile = new QPushButton("Check decision outcome", this);
    layout->addWidget(reconcile);
    connect(reconcile, &QPushButton::clicked, this, [this] {
        if (!authenticated_ || zero(command_))
            return;
        Frame query;
        query.type = Type::GetCommandStatus;
        query.correlation = native::randomIdentity();
        query.fields = {value(Tag::ServiceEpoch, epoch_), value(Tag::CommandId, command_)};
        session_.request(query);
    });
    identity_ = new QLabel("Select a request locally to review its trusted service record.", this);
    identity_->setObjectName("reviewIdentityLabel");
    identity_->setWordWrap(true);
    identity_->setTextFormat(Qt::PlainText);
    layout->addWidget(identity_);
    reviewButton_ = new QPushButton("I have reviewed this request", this);
    reviewButton_->setObjectName("reviewAcknowledgeButton");
    reviewButton_->setEnabled(false);
    reviewButton_->setAutoRepeat(false);
    reviewButton_->installEventFilter(this);
    layout->addWidget(reviewButton_);
    both_ = new QCheckBox(
        "Apply to both inbound and outbound, all users and instances of this path", this);
    both_->setEnabled(false);
    both_->setObjectName("reviewBothScope");
    layout->addWidget(both_);
    action_ = new QComboBox(this);
    action_->setObjectName("reviewDecision");
    action_->addItem("Choose a decision");
    action_->addItem("Block");
    action_->addItem("Allow");
    action_->setEnabled(false);
    layout->addWidget(action_);
    remember_ = new QCheckBox("Create a permanent rule", this);
    remember_->setObjectName("reviewRemember");
    remember_->setEnabled(false);
    layout->addWidget(remember_);
    auto unavailable =
        new QLabel("Once, duration and instance scopes are unavailable in this increment.", this);
    layout->addWidget(unavailable);
    confirm_ = new QPushButton("Confirm selected decision", this);
    confirm_->setObjectName("reviewConfirmButton");
    confirm_->setEnabled(false);
    confirm_->setAutoRepeat(false);
    confirm_->installEventFilter(this);
    layout->addWidget(confirm_);
    connect(connect_, &QPushButton::clicked, this, &ReviewWindow::startLive);
    connect(refresh, &QPushButton::clicked, this, &ReviewWindow::list);
    connect(selectButton, &QPushButton::clicked, this, &ReviewWindow::select);
    connect(action_, &QComboBox::currentIndexChanged, this, &ReviewWindow::choice);
    connect(remember_, &QCheckBox::toggled, this, &ReviewWindow::choice);
    connect(both_, &QCheckBox::toggled, this, &ReviewWindow::choice);
    connect(&session_, &Session::opened, this, [this](bool ok, Frame f) {
        if (ok) {
            status(f);
            list();
            beginIngress();
            if (get(f, Tag::Capabilities) & (1ull << 20)) {
                Frame subscribe;
                subscribe.type = Type::SubscribeEvents;
                subscribe.correlation = native::randomIdentity();
                subscribe.fields = {value(Tag::ServiceEpoch, epoch_), value(Tag::EventMask, 1, 4),
                                    value(Tag::AfterEventSeq, 0)};
                session_.request(subscribe);
            }
        } else
            invalidate("Service identity or protected deployment unavailable.");
    });
    connect(&session_, &Session::received, this, &ReviewWindow::reply);
    connect(&session_, &Session::observation, this, [this](Frame f) {
        if (f.type == Type::Attempt &&
            review_.enqueue(idValue(f, Tag::ServiceEpoch), idValue(f, Tag::RequestId),
                            get(f, Tag::ProfileGeneration)))
            queued_->setText(
                QString("%1 references queued; active review unchanged").arg(review_.queued()));
        else if (f.type == Type::ObservationGap)
            state_->setText("Observation gap. History coverage is incomplete.");
    });
    connect(&session_, &Session::drained, this, [this] {
        if (closing_)
            QTimer::singleShot(0, this, &QWidget::close);
    });
    connect(&timer_, &QTimer::timeout, this, &ReviewWindow::poll);
    timer_.setInterval(200);
    timer_.start();
    qApp->installNativeEventFilter(this);
}
ReviewWindow::~ReviewWindow() { qApp->removeNativeEventFilter(this); }
void ReviewWindow::startLive() {
    if (!session_.idle() || closing_)
        return;
    invalidate("Connecting authenticated review session…");
    session_.open(true, root_ / L"GateBouncerService.exe");
}
void ReviewWindow::invalidate(const QString &reason) {
    if (ingress_)
        ingress_->requestStop();
    for (auto &pair : opens_)
        answerOpen(pair.second, Error::IdentityUnavailable);
    opens_.clear();
    authenticated_ = false;
    connect_->setEnabled(!closing_);
    review_.session({}, {}, 0, false);
    epoch_ = boot_ = {};
    profile_ = 0;
    state_->setText(reason);
    identity_->setText("No active confirmation");
    fence();
    reviewButton_->setEnabled(false);
    action_->setEnabled(false);
    remember_->setEnabled(false);
    both_->setEnabled(false);
}
void ReviewWindow::status(const Frame &f) {
    auto epoch = idValue(f, Tag::ServiceEpoch), boot = idValue(f, Tag::BootId);
    auto profile = get(f, Tag::ProfileGeneration);
    bool ok = get(f, Tag::ReviewProfileState) == 1 &&
              get(f, Tag::EngineState) == unsigned(EngineState::ReadyUnvalidated) &&
              (get(f, Tag::Capabilities) & (1ull << 17));
    if (epoch != epoch_ || boot != boot_ || profile != profile_ || !ok) {
        review_.session(epoch, boot, profile, ok);
        fence();
        identity_->setText("No active confirmation");
    }
    epoch_ = epoch;
    boot_ = boot;
    profile_ = profile;
    authenticated_ = get(f, Tag::ReviewProfileState) == 1;
    state_->setText(!session_.actualOsAuthenticated()
                        ? "Offline fixture — no protection or real decisions"
                    : ok ? "Authenticated review session — engine coverage unvalidated"
                         : "Review unavailable. Existing rules remain owned by the service.");
    connect_->setEnabled(!ok);
}
void ReviewWindow::fence() {
    barrier_ = true;
    armed_ = false;
    cutoff_ = GetTickCount();
    pressBinding_.reset();
    confirm_->setEnabled(false);
    const QEvent::Type types[] = {QEvent::KeyPress,         QEvent::KeyRelease,
                                  QEvent::MouseButtonPress, QEvent::MouseButtonRelease,
                                  QEvent::Shortcut,         QEvent::ShortcutOverride};
    auto objects = findChildren<QObject *>();
    objects.push_back(this);
    for (auto object : objects)
        for (auto type : types)
            QCoreApplication::removePostedEvents(object, type);
}
bool ReviewWindow::nativeEventFilter(const QByteArray &, void *raw, qintptr *) {
    auto message = static_cast<MSG *>(raw);
    if (!message || !message->hwnd)
        return false;
    DWORD process = 0;
    GetWindowThreadProcessId(message->hwnd, &process);
    if (process != GetCurrentProcessId())
        return false;
    bool input = (message->message >= WM_KEYFIRST && message->message <= WM_KEYLAST) ||
                 (message->message >= WM_MOUSEFIRST && message->message <= WM_MOUSELAST);
    return input && (barrier_ || static_cast<LONG>(message->time - cutoff_) <= 0);
}
bool ReviewWindow::eventFilter(QObject *object, QEvent *event) {
    bool press = event->type() == QEvent::MouseButtonPress || event->type() == QEvent::KeyPress;
    bool release =
        event->type() == QEvent::MouseButtonRelease || event->type() == QEvent::KeyRelease;
    if (!press && !release)
        return QWidget::eventFilter(object, event);
    if (barrier_)
        return true;
    if (event->type() == QEvent::KeyPress || event->type() == QEvent::KeyRelease) {
        auto key = static_cast<QKeyEvent *>(event)->key();
        if (key != Qt::Key_Space && key != Qt::Key_Return && key != Qt::Key_Enter)
            return false;
    } else if (static_cast<QMouseEvent *>(event)->button() != Qt::LeftButton)
        return false;
    bool autorepeat =
        event->type() == QEvent::KeyPress && static_cast<QKeyEvent *>(event)->isAutoRepeat();
    if (object == reviewButton_) {
        if (press) {
            if (!review_.reviewPress(review_.generation(), autorepeat))
                return true;
        } else if (review_.reviewRelease(review_.generation())) {
            both_->setEnabled(true);
            action_->setEnabled(true);
            remember_->setEnabled(true);
        }
        return false;
    }
    if (object == confirm_) {
        if (press) {
            pressBinding_ = review_.binding();
            if (autorepeat || !pressBinding_)
                return true;
        } else if (pressBinding_) {
            auto captured = *pressBinding_;
            pressBinding_.reset();
            auto id = native::randomIdentity();
            auto command = review_.confirm(captured, id);
            if (command) {
                command_ = id;
                fence();
                state_->setText("Sending decision. Its outcome may need reconciliation.");
                if (!session_.request(*command))
                    state_->setText("Decision outcome unknown. Use the recorded command ID for "
                                    "reconciliation.");
            }
            return true;
        }
        return false;
    }
    return false;
}
void ReviewWindow::poll() {
    if (closing_) {
        if (session_.idle() && (!ingress_ || !ingress_->running()))
            QTimer::singleShot(0, this, &QWidget::close);
        return;
    }
    if (barrier_ && QApplication::activeWindow() == this) {
        BYTE keys[256]{};
        bool released = GetKeyboardState(keys) != FALSE;
        for (auto key : keys)
            if (key & 0x80)
                released = false;
        if (released) {
            barrier_ = false;
            review_.allInputReleased(review_.generation());
            reviewButton_->setEnabled(review_.active().has_value());
            confirm_->setEnabled(review_.binding().has_value());
        }
    }
    static constexpr unsigned Every = 10;
    static unsigned ticks = 0;
    if (++ticks % Every || !authenticated_ || !session_.idle())
        return;
    Frame f;
    f.type = Type::GetStatus;
    f.correlation = native::randomIdentity();
    session_.request(f);
    if (review_.active()) {
        Frame lookup;
        lookup.type = Type::GetPending;
        lookup.correlation = native::randomIdentity();
        lookup.fields = {value(Tag::ServiceEpoch, epoch_),
                         value(Tag::RequestId, *review_.active())};
        session_.request(lookup);
    }
}
void ReviewWindow::list() {
    if (!authenticated_ || loading_)
        return;
    loading_ = true;
    pageRows_.clear();
    listSnapshot_ = {};
    cursor_ = 0;
    Frame f;
    f.type = Type::ListPending;
    f.correlation = native::randomIdentity();
    f.fields = {value(Tag::ServiceEpoch, epoch_), value(Tag::SnapshotId, listSnapshot_),
                value(Tag::Cursor, 0, 4), value(Tag::Limit, 32, 2)};
    if (!session_.request(f))
        loading_ = false;
}
void ReviewWindow::select() {
    if (!authenticated_ || !zero(command_))
        return;
    int row = rows_->currentRow();
    if (row < 0 || std::size_t(row) >= pending_.size())
        return;
    review_.cancel();
    fence();
    selectCorrelation_ = native::randomIdentity();
    Frame f;
    f.type = Type::GetPending;
    f.correlation = selectCorrelation_;
    f.fields = {value(Tag::ServiceEpoch, epoch_), value(Tag::RequestId, pending_[row].request)};
    session_.request(f);
}
void ReviewWindow::choice() {
    if (!review_.active())
        return;
    auto action = std::uint8_t(action_->currentIndex());
    if (action == 2 && !remember_->isChecked()) {
        QSignalBlocker block(remember_);
        remember_->setChecked(true);
    }
    if (review_.chooseLocal(review_.generation(), action, remember_->isChecked(),
                            both_->isChecked()))
        fence();
    else {
        review_.discardChoice();
        fence();
    }
}
void ReviewWindow::reply(bool ok, const Frame &f, Id correlation) {
    auto open = opens_.find(correlation);
    if (open != opens_.end()) {
        auto wait = open->second;
        opens_.erase(open);
        Error error = Error::Stale;
        if (ok && f.type == Type::PendingRecord &&
            idValue(f, Tag::ServiceEpoch) == wait->reference.epoch &&
            profile_ == wait->reference.profile) {
            auto blob = wire::find(f, Tag::Records);
            std::vector<ii::PendingRecord> records;
            if (blob && ii::unpack(blob->bytes, 1, records) == Error::Ok &&
                records[0].request == wait->reference.request && ii::eligible(records[0])) {
                std::lock_guard<std::mutex> lock(wait->mutex);
                if (!wait->cancelled)
                    error = review_.enqueue(wait->reference.epoch, wait->reference.request,
                                            wait->reference.profile)
                                ? Error::Ok
                                : Error::Capacity;
            }
        }
        answerOpen(wait, error);
        queued_->setText(
            QString("%1 references queued; active review unchanged").arg(review_.queued()));
        return;
    }
    if (!ok) {
        loading_ = false;
        invalidate("Service connection lost. A sent decision may have an unknown outcome.");
        return;
    }
    if (f.type == Type::Status) {
        status(f);
        return;
    }
    if (f.type == Type::ProtocolError) {
        loading_ = false;
        review_.cancel();
        fence();
        state_->setText(QString("Request unavailable (error %1). No new decision was sent.")
                            .arg(get(f, Tag::ErrorCode)));
        return;
    }
    if (f.type == Type::PendingPage) {
        std::vector<ii::PendingRecord> rows;
        auto blob = wire::find(f, Tag::Records);
        if (!blob ||
            ii::unpack(blob->bytes, std::uint16_t(get(f, Tag::Count)), rows) != Error::Ok) {
            invalidate("Invalid service record");
            return;
        }
        pageRows_.insert(pageRows_.end(), rows.begin(), rows.end());
        if (pageRows_.size() > 512) {
            invalidate("Pending capacity exceeded");
            return;
        }
        auto next = std::uint32_t(get(f, Tag::NextCursor));
        if (next != UINT32_MAX) {
            Frame query;
            query.type = Type::ListPending;
            query.correlation = native::randomIdentity();
            query.fields = {value(Tag::ServiceEpoch, epoch_),
                            value(Tag::SnapshotId, idValue(f, Tag::SnapshotId)),
                            value(Tag::Cursor, next, 4), value(Tag::Limit, 32, 2)};
            session_.request(query);
            return;
        }
        pending_ = std::move(pageRows_);
        rows_->clear();
        for (auto &row : pending_)
            rows_->addItem(QString::fromUtf8(reinterpret_cast<const char *>(row.path.data()),
                                             qsizetype(row.path.size())));
        loading_ = false;
        return;
    }
    if (f.type == Type::PendingRecord) {
        std::vector<ii::PendingRecord> rows;
        auto blob = wire::find(f, Tag::Records);
        if (!blob || ii::unpack(blob->bytes, 1, rows) != Error::Ok) {
            invalidate("Invalid trusted record");
            return;
        }
        auto &row = rows[0];
        if (correlation == selectCorrelation_) {
            selectCorrelation_ = {};
            if (!review_.selectLocal(row)) {
                state_->setText("This request cannot be reviewed.");
                return;
            }
            identity_->setText(QString::fromUtf8(reinterpret_cast<const char *>(row.path.data()),
                                                 qsizetype(row.path.size())) +
                               "\nPermanent path · Both directions · All users and instances\n" +
                               (row.flow == 2 ? "Observed attempt: outbound initiated"
                                              : "Observed attempt: inbound initiated"));
            QSignalBlocker a(action_), b(both_), c(remember_);
            action_->setCurrentIndex(0);
            both_->setChecked(false);
            remember_->setChecked(false);
            both_->setEnabled(false);
            action_->setEnabled(false);
            remember_->setEnabled(false);
            fence();
        } else if (!review_.refresh(row)) {
            identity_->setText("Request authority changed or expired. Review it again.");
            fence();
        }
        return;
    }
    if (f.type == Type::MutationAck && correlation == command_) {
        if (get(f, Tag::CommandState) == unsigned(State::Applied) && get(f, Tag::ErrorCode) == 0) {
            state_->setText("Decision recorded by the service. No successful traffic is inferred.");
            command_ = {};
            review_.commandFinished();
            fence();
            list();
        } else
            state_->setText("Decision outcome needs reconciliation. Existing pending is not "
                            "treated as allowed.");
    }
    if (f.type == Type::CommandStatus && idValue(f, Tag::CommandId) == command_) {
        if (get(f, Tag::CommandFound) && get(f, Tag::CommandState) == unsigned(State::Applied) &&
            get(f, Tag::ErrorCode) == 0) {
            state_->setText(
                get(f, Tag::EffectiveKnown)
                    ? "Decision recorded and current policy read back. Traffic remains unproven."
                    : "Decision recorded historically. Its current effect is unknown.");
            command_ = {};
            review_.commandFinished();
            fence();
            list();
        } else
            state_->setText(
                "Decision outcome remains unknown. No automatic mutation retry is permitted.");
    }
}
void ReviewWindow::closeEvent(QCloseEvent *event) {
    review_.cancel();
    fence();
    if (!closing_) {
        closing_ = true;
        if (ingress_)
            ingress_->requestStop();
        for (auto &pair : opens_)
            answerOpen(pair.second, Error::IdentityUnavailable);
        opens_.clear();
        session_.stop();
    }
    if (!session_.idle() || (ingress_ && ingress_->running())) {
        event->ignore();
        state_->setText("Closing the review UI after pending transport finishes…");
        return;
    }
    timer_.stop();
    event->accept();
}
void ReviewWindow::answerOpen(const std::shared_ptr<OpenWait> &wait, Error error) {
    std::lock_guard<std::mutex> lock(wait->mutex);
    wait->error = error;
    wait->done = true;
    wait->changed.notify_all();
}
Error ReviewWindow::ingress(OpenReference reference) {
    auto wait = std::make_shared<OpenWait>();
    wait->reference = reference;
    QMetaObject::invokeMethod(this, [this, wait] {
        if (closing_ || !authenticated_ || wait->reference.epoch != epoch_ ||
            wait->reference.profile != profile_) {
            answerOpen(wait, Error::Stale);
            return;
        }
        if (opens_.size() >= 2) {
            answerOpen(wait, Error::Capacity);
            return;
        }
        auto correlation = native::randomIdentity();
        Frame lookup;
        lookup.type = Type::GetPending;
        lookup.correlation = correlation;
        lookup.fields = {value(Tag::ServiceEpoch, epoch_),
                         value(Tag::RequestId, wait->reference.request)};
        opens_[correlation] = wait;
        if (!session_.request(lookup)) {
            opens_.erase(correlation);
            answerOpen(wait, Error::Capacity);
        }
    });
    std::unique_lock<std::mutex> lock(wait->mutex);
    if (!wait->changed.wait_for(lock, std::chrono::seconds(5), [&] { return wait->done; })) {
        wait->cancelled = true;
        return Error::Timeout;
    }
    return wait->error;
}
void ReviewWindow::beginIngress() {
    if (!session_.actualOsAuthenticated() || !authenticated_)
        return;
    if (ingress_) {
        if (ingress_->running())
            return;
        ingress_.reset();
    }
    native::Handle token;
    HANDLE raw = nullptr;
    native::TokenEvidence identity;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
        return;
    token.reset(raw);
    if (!native::tokenEvidence(token.value, identity))
        return;
    ingress_ = std::make_unique<ReviewIngress>(
        root_, std::move(identity), epoch_, profile_,
        [this](OpenReference reference) { return ingress(reference); });
    if (!ingress_->start()) {
        ingress_.reset();
        queued_->setText("Ordinary review ingress unavailable. Local review remains available.");
    }
}
} // namespace gb::controller
extern "C" __declspec(dllexport) int GateBouncerDecisionStageMain(const wchar_t *root,
                                                                  DWORD session) {
    gb::native::Handle token;
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
        return 31;
    token.reset(raw);
    gb::native::TokenEvidence evidence;
    if (!gb::native::tokenEvidence(token.value, evidence) || !evidence.administrator ||
        !evidence.elevated || evidence.uiAccess || evidence.session != session ||
        evidence.integrity < SECURITY_MANDATORY_HIGH_RID)
        return 32;
    int argc = 1;
    char name[] = "GateBouncerDecisionBootstrap";
    char *argv[] = {name, nullptr};
    QApplication app(argc, argv);
    app.setLibraryPaths(
        {QString::fromWCharArray((std::filesystem::path(root) / L"plugins").c_str())});
    for (const auto file : {L"Inter-Regular.ttf", L"Inter-Medium.ttf", L"Inter-SemiBold.ttf"}) {
        if (QFontDatabase::addApplicationFont(QString::fromWCharArray(
                (std::filesystem::path(root) / L"fonts" / file).c_str())) < 0)
            return 33;
    }
    app.setFont(QFont("Inter", 10));
    gb::controller::ReviewWindow window{std::filesystem::path(root)};
    window.show();
    return app.exec();
}
