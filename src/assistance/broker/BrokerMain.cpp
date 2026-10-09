#include "BrokerLauncher.h"
#include <QCoreApplication>
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);const auto args=app.arguments();
    if(args.size()!=3||args[1]!="--bootstrap-handle")return 2;
    bool ok=false;const auto handle=args[2].toULongLong(&ok);if(!ok||!handle||handle>quint64(UINTPTR_MAX))return 2;
    return Gate::Assistance::Broker::runBrokerFromBootstrap(quintptr(handle));
}
