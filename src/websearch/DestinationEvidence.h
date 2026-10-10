#pragma once
#include <QByteArray>
#include <QString>
#include <QUrl>
#include <optional>

namespace gatebouncer::websearch {
struct HttpResponse;
struct Citation;
// Datos de presentación. Sólo el broker puede cotejarlos con la causa original.
struct Destination {
    QString address;
    quint16 port=0;
    quint8 protocol=0;
    quint64 observedAtMs=0;
    bool operator==(const Destination& other) const;
};
enum class Resource : quint8 { Search=0, Bootstrap4, Bootstrap6, Registry, AdobeEndpoints };
std::optional<QString> canonicalAddress(const QString&);
bool publicDestination(const Destination&);
QUrl bootstrapUrl(const Destination&);
std::optional<QUrl> registryUrl(const QByteArray& bootstrap,const Destination&);
QUrl adobeEndpointsUrl();
bool validResource(Resource,const QUrl&,const std::optional<Destination>&);
std::optional<Citation> registrationEvidence(const HttpResponse&,const Destination&,const QUrl&,quint64);
std::optional<Citation> officialDestinationEvidence(const HttpResponse&,const Destination&,quint64);
}
