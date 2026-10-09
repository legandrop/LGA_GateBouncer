#include "BrokerVault.h"
#include "../configuration/WindowsConfigurationStore.h"
#include <shlobj.h>
#include <sddl.h>
#include <wincrypt.h>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QUuid>
#include <cstring>

namespace Gate::Assistance::Broker {
struct BrokerVault::Impl {
    QString root; int tail; TokenIdentity identity; void *descriptor=nullptr;
    std::vector<Handle> directories; Handle ownerLock; bool ready=false; qint64 lastDispatch=0;
    std::shared_ptr<Configuration::WindowsConfigurationStore> localStore;
    Impl(QString r,int t):root(std::move(r)),tail(t){}
    ~Impl(){if(descriptor)LocalFree(descriptor);}
};
static Handle checkedFile(const QString &path,DWORD access,bool directory,const TokenIdentity &id,bool acl) {
    Handle h(CreateFileW(path.toStdWString().c_str(),access,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
                         FILE_FLAG_OPEN_REPARSE_POINT|(directory?FILE_FLAG_BACKUP_SEMANTICS:0),nullptr));
    BY_HANDLE_FILE_INFORMATION info{};
    if(!h || !GetFileInformationByHandle(h.value,&info) || (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) ||
       bool(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=directory || (!directory&&info.nNumberOfLinks!=1) ||
       (acl&&!exactFileSecurity(h.value,id))) return {};
    return h;
}
BrokerVault::BrokerVault(QString root,int tail):impl_(std::make_unique<Impl>(std::move(root),tail)){}
BrokerVault::~BrokerVault()=default;
std::unique_ptr<BrokerVault> BrokerVault::forLocalConfiguration(std::shared_ptr<Configuration::WindowsConfigurationStore> store) {
    if(!store||!store->facadeAvailable())return {};
    auto vault=std::unique_ptr<BrokerVault>(new BrokerVault({},0));vault->impl_->localStore=std::move(store);return vault;
}
Configuration::CredentialState BrokerVault::localCredentialStatus() {
    const auto store=impl_->localStore;
    return store?store->credentialStatus():Configuration::CredentialState::Unavailable;
}
GeneralReservation BrokerVault::reserveGeneral(Configuration::NetworkPermit &permit,const Configuration::Digest256 &binding,const Configuration::Digest256 &seal) {
    // Current puede retirar la fachada; el Store sigue vivo hasta terminar la reserva.
    const auto store=impl_->localStore;
    if(!store)return {Failure::Unauthorized,false,0};
    return store->reserveGeneral(permit,binding,seal);
}
Failure BrokerVault::withSecret(Configuration::NetworkPermit &permit,const Configuration::Digest256 &binding,const Configuration::Digest256 &seal,const std::function<void(const unsigned char *,size_t)> &consumer) {
    // El consumidor puede retirar la fachada mientras el Store revalida el prestamo.
    const auto store=impl_->localStore;
    return store&&store->withSecret(permit,binding,seal,consumer)?Failure::None:Failure::Unauthorized;
}
std::unique_ptr<BrokerVault> BrokerVault::forCurrentUser() {
    // Esta guarda precede lookup, creacion, lectura y descifrado del perfil real.
    if(!ProductionActivation::approved()) return {};
    TokenIdentity id; if(!tokenIdentity(GetCurrentProcess(),id)||!id.ordinary)return {};
    PWSTR root=nullptr; const HRESULT hr=SHGetKnownFolderPath(FOLDERID_LocalAppData,0,nullptr,&root);
    QString path; if(SUCCEEDED(hr)&&root)path=QString::fromWCharArray(root);if(root)CoTaskMemFree(root);
    if(path.isEmpty())return {};
    auto vault=std::unique_ptr<BrokerVault>(new BrokerVault(path+"/LGA/GateBouncer/Assistance",3));
    return vault->prepare()==Failure::None?std::move(vault):nullptr;
}
Failure BrokerVault::prepare() {
    if(impl_->ready)return exactFileSecurity(impl_->directories.back().value,impl_->identity)?Failure::None:Failure::VaultUnavailable;
    QString root=QDir::fromNativeSeparators(impl_->root);const auto parts=root.split('/');
    if(parts.size()<2 || parts[0].size()!=2 || parts[0][1]!=':' || parts.contains("..") || parts.contains(".") || parts.contains("") || root.contains("//"))return Failure::VaultUnavailable;
    const auto drive=(parts[0]+"/").toStdWString();if(GetDriveTypeW(drive.c_str())!=DRIVE_FIXED)return Failure::VaultUnavailable;
    if(!tokenIdentity(GetCurrentProcess(),impl_->identity)||!impl_->identity.ordinary)return Failure::Unauthorized;
    LPWSTR sid=nullptr;if(!ConvertSidToStringSidW(impl_->identity.user.data(),&sid))return Failure::VaultUnavailable;
    const std::wstring sddl=L"O:"+std::wstring(sid)+L"D:P(A;;FA;;;"+std::wstring(sid)+L")(A;;FA;;;SY)";LocalFree(sid);
    PSECURITY_DESCRIPTOR sd=nullptr;if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&sd,nullptr))return Failure::VaultUnavailable;
    if(impl_->descriptor)LocalFree(impl_->descriptor);
    impl_->descriptor=sd;impl_->directories.clear();
    SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};QString current=parts[0]+"/";
    for(int i=0;i<parts.size();++i) {
        if(i>0)current+=(i==1?"":"/")+parts[i];
        const bool owned=i>=parts.size()-impl_->tail;
        if(owned && !CreateDirectoryW(QDir::toNativeSeparators(current).toStdWString().c_str(),&sa) && GetLastError()!=ERROR_ALREADY_EXISTS)return Failure::VaultUnavailable;
        auto h=checkedFile(QDir::toNativeSeparators(current),FILE_READ_ATTRIBUTES|READ_CONTROL,true,impl_->identity,owned);
        if(!h)return Failure::VaultUnavailable;
        impl_->directories.push_back(std::move(h));
    }
    impl_->root=QDir::toNativeSeparators(root);
    impl_->ownerLock.reset(CreateFileW((impl_->root+"\\owner.lock").toStdWString().c_str(),GENERIC_READ|READ_CONTROL,0,&sa,OPEN_ALWAYS,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    BY_HANDLE_FILE_INFORMATION lockInfo{};
    if(!impl_->ownerLock||!exactFileSecurity(impl_->ownerLock.value,impl_->identity)||!GetFileInformationByHandle(impl_->ownerLock.value,&lockInfo)||
       (lockInfo.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))||lockInfo.nNumberOfLinks!=1)return Failure::VaultUnavailable;
    // Un solo broker por raiz impide reservas perdidas entre dos instancias del usuario.
    impl_->ready=true;return Failure::None;
}
Failure BrokerVault::writeOwned(const QString &name,const unsigned char *bytes,size_t size) {
    if(name!="credential.v1"&&name!="usage.v1")return Failure::VaultUnavailable;
    if(prepare()!=Failure::None || size>16384)return Failure::VaultUnavailable;
    const QString destination=impl_->root+"\\"+name;const auto dest=destination.toStdWString();
    DWORD attr=GetFileAttributesW(dest.c_str());
    if(attr!=INVALID_FILE_ATTRIBUTES) {auto old=checkedFile(destination,GENERIC_READ|READ_CONTROL,false,impl_->identity,true);if(!old)return Failure::VaultUnavailable;}
    else if(GetLastError()!=ERROR_FILE_NOT_FOUND)return Failure::VaultUnavailable;
    const QString pending=impl_->root+"\\pending-"+QUuid::createUuid().toString(QUuid::Id128)+".tmp";
    SECURITY_ATTRIBUTES sa{sizeof(sa),impl_->descriptor,FALSE};Handle file(CreateFileW(pending.toStdWString().c_str(),GENERIC_WRITE|READ_CONTROL,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
    DWORD count=0;if(!file||!exactFileSecurity(file.value,impl_->identity)||!WriteFile(file.value,bytes,DWORD(size),&count,nullptr)||count!=size||!FlushFileBuffers(file.value))return Failure::VaultUnavailable;
    file.reset();const auto temp=pending.toStdWString();
    if(!(attr==INVALID_FILE_ATTRIBUTES?MoveFileExW(temp.c_str(),dest.c_str(),MOVEFILE_WRITE_THROUGH):ReplaceFileW(dest.c_str(),temp.c_str(),nullptr,0,nullptr,nullptr)))return Failure::VaultUnavailable;
    auto written=checkedFile(destination,GENERIC_READ|READ_CONTROL,false,impl_->identity,true);return written?Failure::None:Failure::VaultUnavailable;
}
std::optional<SensitiveBytes> BrokerVault::readOwned(const QString &name,size_t limit) {
    if(name!="credential.v1"&&name!="usage.v1")return {};
    if(prepare()!=Failure::None)return {};
    auto f=checkedFile(impl_->root+"\\"+name,GENERIC_READ|READ_CONTROL,false,impl_->identity,true);LARGE_INTEGER size{};
    if(!f||!GetFileSizeEx(f.value,&size)||size.QuadPart<1||quint64(size.QuadPart)>limit)return {};
    SensitiveBytes bytes(size_t(size.QuadPart));DWORD count=0;
    if(!ReadFile(f.value,bytes.data(),DWORD(bytes.size()),&count,nullptr)||count!=bytes.size())return {};
    return bytes;
}
static QByteArray recordDigest(const unsigned char *data,size_t size) {
    QCryptographicHash hash(QCryptographicHash::Sha256);hash.addData(QByteArrayView("LGA GateBouncer vault v1"));hash.addData(QByteArrayView(reinterpret_cast<const char *>(data),qsizetype(size)));return hash.result();
}
Failure BrokerVault::validateRecord(SensitiveBytes &record,const std::function<void(const unsigned char *,size_t)> &consumer) {
    const auto *d=record.data();const size_t n=record.size();
    if(n<45||n>556||std::memcmp(d,"LGAGBKV1",8)||d[8]!=1||d[9]!=0)return Failure::Corrupt;
    const size_t length=size_t(d[10])|(size_t(d[11])<<8);if(!length||length>512||n!=12+length+32)return Failure::Corrupt;
    for(size_t i=12;i<12+length;++i)if(d[i]<33||d[i]>126)return Failure::Corrupt;
    auto sum=recordDigest(d,12+length);unsigned int difference=0;for(size_t i=0;i<32;++i)difference|=d[12+length+i]^static_cast<unsigned char>(sum[qsizetype(i)]);
    SecureZeroMemory(sum.data(),size_t(sum.size()));if(difference)return Failure::Corrupt;
    if(consumer)consumer(d+12,length);
    return Failure::None;
}
Failure BrokerVault::configure(SensitiveBytes secret) {
    if(impl_->localStore)return Failure::Unauthorized;
    if(prepare()!=Failure::None||!secret.size()||secret.size()>512)return Failure::VaultUnavailable;
    for(size_t i=0;i<secret.size();++i)if(secret.data()[i]<33||secret.data()[i]>126)return Failure::Malformed;
    if(status()==2)return Failure::VaultUnavailable;
    SensitiveBytes record(12+secret.size()+32);auto *d=record.data();std::memcpy(d,"LGAGBKV1",8);d[8]=1;d[10]=static_cast<unsigned char>(secret.size());d[11]=static_cast<unsigned char>(secret.size()>>8);std::memcpy(d+12,secret.data(),secret.size());
    auto sum=recordDigest(d,12+secret.size());std::memcpy(d+12+secret.size(),sum.data(),32);SecureZeroMemory(sum.data(),size_t(sum.size()));
    DATA_BLOB plain{DWORD(record.size()),record.data()}, encrypted{};
    if(!CryptProtectData(&plain,L"LGA GateBouncer credential",nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&encrypted))return Failure::VaultUnavailable;
    Failure result=Failure::Corrupt;
    if(encrypted.pbData&&encrypted.cbData&&encrypted.cbData<=16376) {
        SensitiveBytes envelope(8+encrypted.cbData);std::memcpy(envelope.data(),"GBE1",4);for(int i=0;i<4;++i)envelope.data()[4+i]=static_cast<unsigned char>(encrypted.cbData>>(8*i));std::memcpy(envelope.data()+8,encrypted.pbData,encrypted.cbData);result=writeOwned("credential.v1",envelope.data(),envelope.size());
    }
    if(encrypted.pbData)LocalFree(encrypted.pbData);
    return result;
}
Failure BrokerVault::withSecret(const std::function<void(const unsigned char *,size_t)> &consumer) {
    if(impl_->localStore)return Failure::Unauthorized;
    auto envelope=readOwned("credential.v1",16384);if(!envelope||envelope->size()<9||std::memcmp(envelope->data(),"GBE1",4))return Failure::Corrupt;
    DWORD length=0;for(int i=0;i<4;++i)length|=DWORD(envelope->data()[4+i])<<(8*i);if(!length||length>16376||envelope->size()!=8+size_t(length))return Failure::Corrupt;
    DATA_BLOB encrypted{length,envelope->data()+8}, output{};
    if(!CryptUnprotectData(&encrypted,nullptr,nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&output))return Failure::Corrupt;
    Failure result=Failure::Corrupt;
    if(output.pbData&&output.cbData>=45&&output.cbData<=556) {SensitiveBytes record(output.cbData);std::memcpy(record.data(),output.pbData,output.cbData);SecureZeroMemory(output.pbData,output.cbData);result=validateRecord(record,consumer);}
    if(output.pbData){SecureZeroMemory(output.pbData,output.cbData);LocalFree(output.pbData);}return result;
}
quint8 BrokerVault::status() {
    if(impl_->localStore){const auto state=localCredentialStatus();return state==Configuration::CredentialState::Absent?0:(state==Configuration::CredentialState::Stored?1:2);}
    if(prepare()!=Failure::None)return 2;
    const auto file=(impl_->root+"\\credential.v1").toStdWString();
    if(GetFileAttributesW(file.c_str())==INVALID_FILE_ATTRIBUTES)return GetLastError()==ERROR_FILE_NOT_FOUND?0:2;
    return withSecret({})==Failure::None?1:2;
}
Failure BrokerVault::forget() {
    if(impl_->localStore)return Failure::Unauthorized;
    if(prepare()!=Failure::None)return Failure::VaultUnavailable;
    if(status()==0)return Failure::None;
    auto file=checkedFile(impl_->root+"\\credential.v1",DELETE|READ_CONTROL|FILE_READ_ATTRIBUTES,false,impl_->identity,true);FILE_DISPOSITION_INFO disposition{TRUE};
    return file&&SetFileInformationByHandle(file.value,FileDispositionInfo,&disposition,sizeof(disposition))?Failure::None:Failure::VaultUnavailable;
}
Failure BrokerVault::reserveAttempt() {
    if(impl_->localStore)return Failure::Unauthorized;
    if(prepare()!=Failure::None)return Failure::VaultUnavailable;
    const auto now=QDateTime::currentSecsSinceEpoch();const auto day=now/86400;quint64 count=0,last=0,oldDay=0;
    const auto file=(impl_->root+"\\usage.v1").toStdWString();
    if(GetFileAttributesW(file.c_str())!=INVALID_FILE_ATTRIBUTES) {
        auto bytes=readOwned("usage.v1",32);if(!bytes||bytes->size()!=32||std::memcmp(bytes->data(),"GBAU",4)||bytes->data()[4]!=1)return Failure::Corrupt;
        for(int i=5;i<8;++i)if(bytes->data()[i])return Failure::Corrupt;
        auto n=[&](int p){quint64 v=0;for(int i=0;i<8;++i)v|=quint64(bytes->data()[p+i])<<(8*i);return v;};oldDay=n(8);count=n(16);last=n(24);
        if(count>60||last/86400!=oldDay||quint64(now)<last)return Failure::RateLimited;
    } else if(GetLastError()!=ERROR_FILE_NOT_FOUND)return Failure::VaultUnavailable;
    if(oldDay!=quint64(day))count=0;
    const auto tick=GetTickCount64();if(count>=60||(impl_->lastDispatch&&tick-quint64(impl_->lastDispatch)<10000)||(last&&quint64(now)<last+10))return Failure::RateLimited;
    SensitiveBytes record(32);std::memcpy(record.data(),"GBAU",4);record.data()[4]=1;
    auto put=[&](int p,quint64 v){for(int i=0;i<8;++i)record.data()[p+i]=static_cast<unsigned char>(v>>(8*i));};put(8,quint64(day));put(16,count+1);put(24,quint64(now));
    const auto result=writeOwned("usage.v1",record.data(),record.size());if(result==Failure::None)impl_->lastDispatch=qint64(tick);return result;
}
}
