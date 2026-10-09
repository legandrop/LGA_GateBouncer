#include "WindowsConfigurationStore.h"
#include "ConfigurationAuthority.h"
#include "ConfigurationCodec.h"
#include "ProviderEntitlementInternal.h"
#include "../broker/BrokerVault.h"
#include <chrono>
#include <shlobj.h>
#include <sddl.h>
#include <QDir>
#include <cstring>
#include <limits>
#include <algorithm>

namespace Gate::Assistance::Configuration {
namespace {
using Broker::Handle;
struct FileStamp { BY_HANDLE_FILE_INFORMATION info{};FILE_ID_INFO identity{};bool captured=false; };
bool sameId(const FileStamp &a,const FileStamp &b){return a.captured&&b.captured&&a.identity.VolumeSerialNumber==b.identity.VolumeSerialNumber&&!std::memcmp(a.identity.FileId.Identifier,b.identity.FileId.Identifier,16);}
bool sameFile(const FileStamp &a,const FileStamp &b){return sameId(a,b)&&a.info.nFileSizeHigh==b.info.nFileSizeHigh&&a.info.nFileSizeLow==b.info.nFileSizeLow&&CompareFileTime(&a.info.ftLastWriteTime,&b.info.ftLastWriteTime)==0;}
bool stamp(HANDLE h,FileStamp &s,bool directory,const Broker::TokenIdentity &id,bool acl){s.captured=false;return s.captured=GetFileType(h)==FILE_TYPE_DISK&&GetFileInformationByHandle(h,&s.info)&&GetFileInformationByHandleEx(h,FileIdInfo,&s.identity,sizeof(s.identity))&&!(s.info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)&&bool(s.info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==directory&&(directory||s.info.nNumberOfLinks==1)&&(!acl||Broker::exactFileSecurity(h,id));}
std::uint64_t fileSize(const FileStamp &s){return (std::uint64_t(s.info.nFileSizeHigh)<<32)|s.info.nFileSizeLow;}
struct PublicationIdentity { FileStamp file;Digest256 bytesDigest{};bool captured=false; };
bool capturePublication(HANDLE h,const Broker::SensitiveBytes &bytes,const char *domain,const Broker::TokenIdentity &id,PublicationIdentity &p){
    p.captured=false;LARGE_INTEGER size{};if(!stamp(h,p.file,false,id,true)||!GetFileSizeEx(h,&size)||size.QuadPart<0||std::uint64_t(size.QuadPart)!=bytes.size()||fileSize(p.file)!=bytes.size())return false;
    p.bytesDigest=digest(domain,bytes.data(),bytes.size());return p.captured=nonzero(p.bytesDigest);
}
struct ReadResult { StorageState state=StorageState::Unreadable;DWORD error=0;std::optional<Detail::PersistentRecord> record;FileStamp file;Digest256 envelopeDigest{}; };
bool sameEntitlementPublication(const ReadResult &read,const Detail::EntitlementContext &proof) {
    return read.record&&read.state==StorageState::Ready&&read.record->secret.size()&&
        read.file.identity.VolumeSerialNumber==proof.volume&&fileSize(read.file)==proof.size&&
        !std::memcmp(read.file.identity.FileId.Identifier,proof.fileId.data(),16)&&
        ((std::uint64_t(read.file.info.ftLastWriteTime.dwHighDateTime)<<32)|read.file.info.ftLastWriteTime.dwLowDateTime)==proof.writeTime&&
        read.envelopeDigest==proof.envelope&&read.record->integrity==proof.integrity&&
        read.record->committedRevision==proof.committedRevision&&
        read.record->metadata.storeInstance==proof.image.snapshot.storeInstance&&
        read.record->metadata.epochs.credential==proof.image.snapshot.epochs.credential&&
        read.record->metadata.credential==CredentialState::Stored;
}
bool validComponent(const QString &part){
    if(part.isEmpty()||part=="."||part==".."||part.endsWith('.')||part.endsWith(' '))return false;
    for(auto c:part)if(c.unicode()<32||QStringLiteral("<>:\\|?*\"").contains(c))return false;
    const auto stem=part.section('.',0,0).toUpper();if(stem=="CON"||stem=="PRN"||stem=="AUX"||stem=="NUL")return false;
    if(stem.size()==4&&(stem.startsWith("COM")||stem.startsWith("LPT"))&&stem[3]>='1'&&stem[3]<='9')return false;
    return true;
}
}
struct WindowsConfigurationStore::Impl {
    std::wstring root;std::shared_ptr<const LocalConfigurationPermission> permission;Broker::TokenIdentity identity;
    void *descriptor=nullptr;std::vector<Handle> directories;std::vector<FileStamp> ancestors;std::vector<std::wstring> paths;
    Handle ownerLock;StorageState preparation=StorageState::Uninitialized;std::optional<Digest256> expectedDigest;std::optional<FileStamp> expectedFile;bool loaded=false;
    std::mutex mutex;std::weak_ptr<Detail::Authority> authority;bool authorityBound=false;
    std::uint64_t lastDispatch=0;
    std::function<void(const std::wstring &)> beforePublication;
    Impl(std::wstring r,std::shared_ptr<const LocalConfigurationPermission> p,std::function<void(const std::wstring &)> observer):root(std::move(r)),permission(std::move(p)),beforePublication(std::move(observer)){}
    ~Impl(){if(descriptor)LocalFree(descriptor);}
    bool current(){
        if(!permission||!permission->current()||!ownerLock||directories.empty())return false;
        Broker::TokenIdentity token;if(!Broker::tokenIdentity(GetCurrentProcess(),token)||!Broker::sameIdentity(identity,token))return false;
        for(std::size_t i=0;i<directories.size();++i){FileStamp held,opened;const bool own=i+2>=directories.size();
            Handle h(CreateFileW(paths[i].c_str(),FILE_READ_ATTRIBUTES|READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr));
            if(!h||!stamp(directories[i].value,held,true,identity,own)||!stamp(h.value,opened,true,identity,own)||!sameId(held,ancestors[i])||!sameId(held,opened))return false;
        }
        FileStamp lock;return stamp(ownerLock.value,lock,false,identity,true);
    }
    StorageState prepare(){
        if(ownerLock)return current()?StorageState::Ready:StorageState::UnsafeRoot;
        if(!permission||!permission->current()||!Broker::tokenIdentity(GetCurrentProcess(),identity)||!identity.ordinary)return StorageState::UnsafeRoot;
        const QString q=QDir::fromNativeSeparators(QString::fromStdWString(root));const auto parts=q.split('/');
        if(parts.size()<4||parts[0].size()!=2||parts[0][1]!=':'||parts[0][0].toUpper()<'A'||parts[0][0].toUpper()>'Z'||parts.contains("")||q.contains("//"))return StorageState::UnsafeRoot;
        for(int i=1;i<parts.size();++i)if(!validComponent(parts[i]))return StorageState::UnsafeRoot;
        const auto drive=(parts[0]+"/").toStdWString();DWORD flags=0;if(GetDriveTypeW(drive.c_str())!=DRIVE_FIXED||!GetVolumeInformationW(drive.c_str(),nullptr,0,nullptr,nullptr,&flags,nullptr,0)||!(flags&FILE_PERSISTENT_ACLS))return StorageState::UnsafeRoot;
        LPWSTR sid=nullptr;if(!ConvertSidToStringSidW(identity.user.data(),&sid))return StorageState::Unreadable;
        const std::wstring sddl=L"O:"+std::wstring(sid)+L"D:P(A;;FA;;;"+std::wstring(sid)+L")(A;;FA;;;SY)";LocalFree(sid);
        PSECURITY_DESCRIPTOR sd=nullptr;if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&sd,nullptr))return StorageState::Unreadable;
        if(descriptor)LocalFree(descriptor);
        descriptor=sd;SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};
        directories.clear();ancestors.clear();paths.clear();QString path=parts[0]+"/";
        for(int i=0;i<parts.size();++i){if(i>0)path+=(i==1?"":"/")+parts[i];const bool own=i>=parts.size()-2;const auto native=QDir::toNativeSeparators(path).toStdWString();
            if(i>0&&!CreateDirectoryW(native.c_str(),own?&sa:nullptr)){const DWORD error=GetLastError();if(error!=ERROR_ALREADY_EXISTS)return StorageState::Unreadable;}
            Handle h(CreateFileW(native.c_str(),FILE_READ_ATTRIBUTES|READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr));FileStamp info;
            if(!h||!stamp(h.value,info,true,identity,own)||(i&&info.identity.VolumeSerialNumber!=ancestors[0].identity.VolumeSerialNumber))return StorageState::UnsafeRoot;
            paths.push_back(native);ancestors.push_back(info);directories.push_back(std::move(h));
        }
        root=paths.back();ownerLock.reset(CreateFileW((root+L"\\owner.lock").c_str(),GENERIC_READ|READ_CONTROL,0,&sa,OPEN_ALWAYS,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));const DWORD error=ownerLock?0:GetLastError();
        if(!ownerLock)return error==ERROR_SHARING_VIOLATION?StorageState::Busy:StorageState::Unreadable;
        FileStamp info;if(!stamp(ownerLock.value,info,false,identity,true)){ownerLock.reset();return StorageState::UnsafeRoot;}
        return current()?StorageState::Ready:StorageState::UnsafeRoot;
    }
    ReadResult read(){
        ReadResult result;if(!current()){result.state=StorageState::UnsafeRoot;return result;}
        Handle file(CreateFileW((root+L"\\configuration.v2").c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        if(!file){result.error=GetLastError();result.state=result.error==ERROR_FILE_NOT_FOUND?StorageState::Uninitialized:(result.error==ERROR_SHARING_VIOLATION?StorageState::Busy:StorageState::Unreadable);if(!current())result.state=StorageState::UnsafeRoot;return result;}
        if(!stamp(file.value,result.file,false,identity,true)){result.state=StorageState::UnsafeRoot;return result;}
        LARGE_INTEGER size{};if(!GetFileSizeEx(file.value,&size)){result.error=GetLastError();return result;}
        if(size.QuadPart<17||size.QuadPart>16400){result.state=StorageState::Corrupt;return result;}
        Broker::SensitiveBytes bytes(std::size_t(size.QuadPart));DWORD count=0;if(!ReadFile(file.value,bytes.data(),DWORD(bytes.size()),&count,nullptr)){result.error=GetLastError();return result;}
        if(count!=bytes.size())return result;
        unsigned char extra=0;if(!ReadFile(file.value,&extra,1,&count,nullptr)){result.error=GetLastError();return result;}if(count)return result;
        FileStamp after;if(!stamp(file.value,after,false,identity,true)||!sameFile(result.file,after)||!current()){result.state=StorageState::UnsafeRoot;return result;}
        result.envelopeDigest=digest("LGA_GATEBOUNCER_CONFIGURATION_PUBLICATION_V1",bytes.data(),bytes.size());if(!nonzero(result.envelopeDigest))return result;
        auto plain=Detail::unprotectRecord(bytes);if(plain)result.record=Detail::decodeRecord(*plain);result.state=result.record?StorageState::Ready:StorageState::Corrupt;return result;
    }
    bool legacyPresent(){Handle legacy(CreateFileW((root+L"\\credential.v1").c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));if(legacy)return true;return GetLastError()!=ERROR_FILE_NOT_FOUND;}
    void remember(const ReadResult &r){expectedDigest=r.record?std::optional<Digest256>(r.record->integrity):std::nullopt;expectedFile=(r.state==StorageState::Ready||r.state==StorageState::Corrupt)?std::optional<FileStamp>(r.file):std::nullopt;loaded=true;}
    bool samePrecedent(const ReadResult &r){return expectedDigest==(r.record?std::optional<Digest256>(r.record->integrity):std::nullopt)&&bool(expectedFile)==(r.state==StorageState::Ready||r.state==StorageState::Corrupt)&&(!expectedFile||sameFile(*expectedFile,r.file));}
    void cleanup(const std::wstring &path,const FileStamp &id){Handle h(CreateFileW(path.c_str(),DELETE|READ_CONTROL|FILE_READ_ATTRIBUTES,0,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));FileStamp info;if(h&&stamp(h.value,info,false,identity,true)&&sameId(id,info)){FILE_DISPOSITION_INFO disposition{TRUE};SetFileInformationByHandle(h.value,FileDispositionInfo,&disposition,sizeof(disposition));}}
};
WindowsConfigurationStore::WindowsConfigurationStore(std::wstring root,std::shared_ptr<const LocalConfigurationPermission> permission,std::function<void(const std::wstring &)> observer):impl_(std::make_unique<Impl>(std::move(root),std::move(permission),std::move(observer))){}
WindowsConfigurationStore::~WindowsConfigurationStore()=default;
std::unique_ptr<WindowsConfigurationStore> WindowsConfigurationStore::forCurrentUser(ConfigurationController &controller){
    if(!controller.permission_||!controller.permission_->current())return {};
    PWSTR path=nullptr;const HRESULT hr=SHGetKnownFolderPath(FOLDERID_LocalAppData,0,nullptr,&path);std::wstring root;if(SUCCEEDED(hr)&&path)root=path;if(path)CoTaskMemFree(path);if(root.empty())return {};
    auto store=std::unique_ptr<WindowsConfigurationStore>(new WindowsConfigurationStore(root+L"\\LGA\\GateBouncer\\Assistance",controller.permission_));store->reload(controller);return store;
}
static ConfigurationSnapshot effective(const Detail::PersistentRecord &r){auto s=r.metadata;s.search.reset();s.webConsent.granted=false;return s;}
ConfigurationSnapshot WindowsConfigurationStore::reload(ConfigurationController &controller){
    std::lock_guard<std::mutex> operation(impl_->mutex);
    if(impl_->authorityBound&&impl_->authority.lock()!=controller.authority_){auto denied=controller.snapshot();denied.storage=StorageState::UnsafeRoot;denied.credential=CredentialState::Unavailable;Detail::revokeReceipts(denied);return denied;}
    impl_->authority=controller.authority_;impl_->authorityBound=true;
    const bool firstLoad=!impl_->loaded;
    impl_->preparation=impl_->prepare();ReadResult read;if(impl_->preparation==StorageState::Ready){read=impl_->read();if(read.state==StorageState::Uninitialized&&impl_->legacyPresent())read.state=StorageState::Unreadable;}else read.state=impl_->preparation;
    impl_->remember(read);auto a=controller.authority_;std::lock_guard<std::mutex> lock(a->mutex);const auto previousEpochs=a->snapshot.epochs;const auto previousStore=a->snapshot.storeInstance;
    if(nonzero(a->pendingTicket))a->failureLatched=true;
    if(!firstLoad&&!Detail::advance(*a))return a->snapshot;
    a->pendingTicket={};const auto transitionEpochs=a->snapshot.epochs;const auto viewRevision=a->snapshot.revision;
    if(read.record){auto s=effective(*read.record);s.epochs.session=transitionEpochs.session;s.epochs.retrieval=transitionEpochs.retrieval;s.epochs.entitlement=previousEpochs.entitlement;s.epochs.providerPolicy=previousEpochs.providerPolicy;s.revision=firstLoad?read.record->committedRevision:viewRevision;
        a->snapshot=s;a->observedRecord=s;a->committedRevision=read.record->committedRevision;
    }else {a->snapshot=ConfigurationSnapshot{};a->snapshot.storeInstance=previousStore;a->snapshot.epochs.session=transitionEpochs.session;a->snapshot.epochs.retrieval=transitionEpochs.retrieval;a->snapshot.revision=viewRevision;a->snapshot.storage=read.state;a->snapshot.credential=read.state==StorageState::Uninitialized?CredentialState::Absent:(read.state==StorageState::Corrupt?CredentialState::Corrupt:CredentialState::Unavailable);a->observedRecord.reset();a->committedRevision=0;}
    if(a->failureLatched){a->snapshot.storage=StorageState::IoUncertain;a->snapshot.epochs=transitionEpochs;Detail::revokeReceipts(a->snapshot);}return a->snapshot;
}
MutationResult WindowsConfigurationStore::apply(ConfigurationController &controller,MutationTicket ticket){
    std::lock_guard<std::mutex> operation(impl_->mutex);
    PublicationObservation observation;auto &d=ticket.data_;if(!d||d->authority.lock()!=controller.authority_||impl_->authority.lock()!=controller.authority_)return controller.finish(std::move(ticket),std::move(observation));
    const auto ticketCurrent=[&]{auto a=controller.authority_;std::lock_guard<std::mutex> lock(a->mutex);return a->alive&&a->pendingTicket==d->ticket&&a->ordinary&&a->ordinary();};
    if(!ticketCurrent())return controller.finish(std::move(ticket),std::move(observation));
    auto before=impl_->read();const bool usable=before.state==StorageState::Ready||before.state==StorageState::Uninitialized||(before.state==StorageState::Corrupt&&d->verb==ConfigurationVerb::Forget);
    if(!impl_->loaded||!usable||!impl_->samePrecedent(before)||(before.state==StorageState::Uninitialized&&impl_->legacyPresent())){observation.primaryError_=before.error;return controller.finish(std::move(ticket),std::move(observation));}
    Detail::PersistentRecord candidate;candidate.metadata=d->candidate;candidate.committedRevision=d->committedRevision;
    if(before.record){candidate.profileRevision=before.record->profileRevision;candidate.search=before.record->search;candidate.evidence=before.record->evidence;if(d->candidate.credential==CredentialState::Stored&&d->verb!=ConfigurationVerb::Store)candidate.secret=std::move(before.record->secret);
        if(!d->failureLatchedAtBegin&&!d->candidate.webConsent.granted&&d->candidate.epochs.webConsent==before.record->metadata.epochs.webConsent)candidate.metadata.webConsent=before.record->metadata.webConsent;
    }
    if(d->verb==ConfigurationVerb::Store)candidate.secret=std::move(d->secret);
    if(d->verb==ConfigurationVerb::Search&&d->candidate.search){const auto &s=*d->candidate.search;candidate.search=Detail::SearchPreference{s.provider,s.configurationBinding,s.providerPolicyEpoch};}
    auto plain=Detail::encodeRecord(candidate);auto encrypted=plain?Detail::protectRecord(*plain):std::nullopt;if(!encrypted)return controller.finish(std::move(ticket),std::move(observation));
    const auto candidateDigest=digest("LGA_GATEBOUNCER_CONFIGURATION_V2",plain->data(),plain->size()-32);
    Id128 nonce{};if(!Broker::randomId(nonce))return controller.finish(std::move(ticket),std::move(observation));const char hex[]="0123456789abcdef";std::wstring pending=impl_->root+L"\\pending-";for(auto b:nonce){pending+=wchar_t(hex[b>>4]);pending+=wchar_t(hex[b&15]);}pending+=L".tmp";
    SECURITY_ATTRIBUTES sa{sizeof(sa),impl_->descriptor,FALSE};Handle file(CreateFileW(pending.c_str(),GENERIC_WRITE|READ_CONTROL,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));FileStamp temporary;DWORD count=0;
    if(!file){observation.primaryError_=GetLastError();return controller.finish(std::move(ticket),std::move(observation));}
    bool written=stamp(file.value,temporary,false,impl_->identity,true);if(written){written=WriteFile(file.value,encrypted->data(),DWORD(encrypted->size()),&count,nullptr)!=FALSE;if(!written)observation.primaryError_=GetLastError();if(written&&count!=encrypted->size()){observation.primaryError_=ERROR_WRITE_FAULT;written=false;}}if(written){written=FlushFileBuffers(file.value)!=FALSE;if(!written)observation.primaryError_=GetLastError();}
    PublicationIdentity prepared;if(written){written=capturePublication(file.value,*encrypted,"LGA_GATEBOUNCER_CONFIGURATION_PUBLICATION_V1",impl_->identity,prepared);if(written)temporary=prepared.file;}file.reset();
    auto preceding=impl_->read();if(!written||!impl_->current()||!impl_->samePrecedent(preceding)||!ticketCurrent()){impl_->cleanup(pending,temporary);return controller.finish(std::move(ticket),std::move(observation));}
    if(impl_->beforePublication){try{impl_->beforePublication(pending);}catch(...){impl_->cleanup(pending,temporary);observation.primaryError_=ERROR_OPERATION_ABORTED;return controller.finish(std::move(ticket),std::move(observation));}}
    if(!ticketCurrent()){impl_->cleanup(pending,temporary);return controller.finish(std::move(ticket),std::move(observation));}
    const std::wstring target=impl_->root+L"\\configuration.v2";const BOOL published=before.state==StorageState::Uninitialized?MoveFileExW(pending.c_str(),target.c_str(),MOVEFILE_WRITE_THROUGH):ReplaceFileW(target.c_str(),pending.c_str(),nullptr,0,nullptr,nullptr);const DWORD primary=published?0:GetLastError();
    observation.apiSuccess_=published!=FALSE;observation.primaryError_=primary;auto after=impl_->read();
    if(after.record){observation.observed_=effective(*after.record);observation.observed_->epochs.session=d->candidate.epochs.session;observation.observed_->epochs.retrieval=d->candidate.epochs.retrieval;observation.observed_->epochs.providerPolicy=d->candidate.epochs.providerPolicy;observation.observed_->epochs.entitlement=d->candidate.epochs.entitlement;observation.observed_->revision=d->candidate.revision;observation.committedRevision_=after.record->committedRevision;
        auto canonical=Detail::encodeRecord(*after.record);bool exact=canonical&&canonical->size()==plain->size();if(exact){unsigned difference=0;for(std::size_t i=0;i<plain->size();++i)difference|=plain->data()[i]^canonical->data()[i];exact=difference==0;}
        observation.exactCandidate_=exact&&after.record->integrity==candidateDigest&&after.record->metadata.storeInstance==d->candidate.storeInstance&&after.record->committedRevision==d->committedRevision;
        if(observation.exactCandidate_)observation.observed_=d->candidate;
        observation.attributed_=prepared.captured&&sameId(prepared.file,after.file)&&fileSize(prepared.file)==fileSize(after.file)&&prepared.bytesDigest==after.envelopeDigest&&impl_->current()&&ticketCurrent();
    }
    impl_->remember(after);impl_->cleanup(pending,temporary);return controller.finish(std::move(ticket),std::move(observation));
}
bool WindowsConfigurationStore::withSecret(NetworkPermit &permit,const Digest256 &binding,const Digest256 &seal,const std::function<void(const unsigned char *,std::size_t)> &consumer){
    if(!consumer||!permit.current(ActivationStage::BeforeSecret,binding,seal))return false;
    ReadResult read;{std::lock_guard<std::mutex> operation(impl_->mutex);if(!permit.lease_||permit.lease_->authority.lock()!=impl_->authority.lock())return false;read=impl_->read();if(!read.record||!impl_->samePrecedent(read)||!read.record->secret.size()||read.record->metadata.storeInstance!=permit.lease_->image.snapshot.storeInstance)return false;}
    if(!permit.current(ActivationStage::BeforeSecret,binding,seal))return false;
    try{consumer(read.record->secret.data(),read.record->secret.size());}catch(...){return false;}
    {std::lock_guard<std::mutex> operation(impl_->mutex);auto after=impl_->read();if(!after.record||!impl_->samePrecedent(after)||after.record->integrity!=read.record->integrity)return false;}
    return permit.current(ActivationStage::BeforeSecret,binding,seal);
}
std::unique_ptr<Detail::EntitlementContext> WindowsConfigurationStore::captureEntitlementContext(
    ConfigurationController &controller,const std::shared_ptr<WindowsConfigurationStore> &owner) {
    if(owner.get()!=this)return {};
    std::lock_guard<std::mutex> operation(impl_->mutex);
    const auto a=controller.authority_;
    if(impl_->authority.lock()!=a)return {};
    const auto read=impl_->read();
    if(!read.record||read.state!=StorageState::Ready||!impl_->samePrecedent(read)||
        !read.record->secret.size()||read.record->metadata.credential!=CredentialState::Stored)return {};
    std::lock_guard<std::mutex> lock(a->mutex);
    if(!a->alive||a->failureLatched||nonzero(a->pendingTicket)||!a->entitlement||!a->entitlement->catalog||
        a->snapshot.storage!=StorageState::Ready||a->snapshot.credential!=CredentialState::Stored||
        a->snapshot.storeInstance!=read.record->metadata.storeInstance||
        a->snapshot.epochs.credential!=read.record->metadata.epochs.credential||
        a->committedRevision!=read.record->committedRevision)return {};
    auto proof=std::unique_ptr<Detail::EntitlementContext>(new Detail::EntitlementContext);
    proof->store=owner;proof->authority=a;proof->image=Detail::image(*a);
    proof->capability=a->capability;proof->capabilityVerb=a->capabilityVerb;
    proof->capabilityExpiry=a->capabilityExpiry;proof->pendingTicket=a->pendingTicket;
    proof->catalogGeneration=a->entitlement->catalog->generation_;
    proof->floorGeneration=a->entitlement->floorGeneration;
    proof->volume=read.file.identity.VolumeSerialNumber;proof->size=fileSize(read.file);
    std::copy_n(read.file.identity.FileId.Identifier,16,proof->fileId.begin());
    proof->writeTime=(std::uint64_t(read.file.info.ftLastWriteTime.dwHighDateTime)<<32)|read.file.info.ftLastWriteTime.dwLowDateTime;
    proof->envelope=read.envelopeDigest;proof->integrity=read.record->integrity;
    proof->committedRevision=read.record->committedRevision;
    return proof;
}
EntitlementReviewResult WindowsConfigurationStore::finishEntitlementReview(ConfigurationController &controller,
    Detail::EntitlementContext &&proof,Detail::ReviewedSelection &&selection,bool explicitlySelect) {
    auto result=selection.result;
    const auto reject=[&](ReviewCause cause){result.recognized=false;result.decision=ReviewDecision::PendingReview;result.cause=cause;return result;};
    const auto owner=proof.store.lock();const auto a=proof.authority.lock();
    if(owner.get()!=this||!a||a!=controller.authority_)return reject(ReviewCause::LocalPublicationChanged);
    std::lock_guard<std::mutex> operation(impl_->mutex);
    if(impl_->authority.lock()!=a)return reject(ReviewCause::LocalPublicationChanged);
    const auto read=impl_->read();
    if(!impl_->samePrecedent(read)||!sameEntitlementPublication(read,proof))return reject(ReviewCause::LocalPublicationChanged);
    std::lock_guard<std::mutex> lock(a->mutex);
    if(!Detail::entitlementImageCurrent(*a,proof)||
        a->entitlement->catalog!=selection.catalog||a->entitlement->catalog->generation_!=proof.catalogGeneration||
        !result.recognized)return reject(ReviewCause::LocalPublicationChanged);
    if(!Detail::entitlementFloorsCurrent(*a->entitlement,selection))return reject(ReviewCause::Rollback);
    const auto elapsed=(GetTickCount64()-selection.checkedTick)/1000;
    const auto now=impl_->permission->purpose_==LocalConfigurationPermission::Purpose::PrivateFixture?
        selection.checkedUtc+elapsed:std::uint64_t(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    if(selection.provider.evidence!=EvidenceState::Missing&&
        (now<selection.artifact.reviewedAt||now<selection.provider.notBefore||now>=selection.provider.notAfter)) {
        selection.provider.evidence=EvidenceState::Expired;result.decision=ReviewDecision::PendingReview;result.cause=ReviewCause::ReviewExpired;
    }
    if(!explicitlySelect)return result;
    const auto &runtime=*a->entitlement;
    if(runtime.publishedReview==selection.artifact.revision&&runtime.publishedImage&&
        *runtime.publishedImage==Detail::image(*a)&&a->provider==selection.provider) {
        result.unchanged=true;return result;
    }
    const auto maximum=std::numeric_limits<std::uint64_t>::max();
    if(runtime.floorGeneration==maximum||a->snapshot.revision==maximum||a->snapshot.epochs.entitlement==maximum||
        a->snapshot.epochs.retrieval==maximum||a->transitionBarrier==maximum) {
        a->alive=false;return reject(ReviewCause::RevisionExhausted);
    }
    // Preparar todas las asignaciones antes de publicar la transicion.
    auto nextState=std::make_shared<Detail::EntitlementState>(runtime);auto nextImage=Detail::image(*a);
    ++nextImage.snapshot.revision;++nextImage.snapshot.epochs.entitlement;
    ++nextImage.snapshot.epochs.retrieval;++nextImage.barrier;
    if(!(a->provider.notice==selection.provider.notice))nextImage.snapshot.modelConsent.granted=false;
    nextImage.provider=selection.provider;
    Detail::rememberEntitlement(*nextState,selection,nextImage);
    a->snapshot=std::move(nextImage.snapshot);a->provider=std::move(selection.provider);
    a->transitionBarrier=nextImage.barrier;a->capability={};a->capabilityExpiry=0;
    a->entitlement=std::move(nextState);result.published=true;return result;
}
bool WindowsConfigurationStore::replaceEntitlementCatalog(ConfigurationController &controller,
    Detail::EntitlementContext &&proof,std::shared_ptr<const ReviewedProviderCatalog> catalog) {
    const auto owner=proof.store.lock();const auto a=proof.authority.lock();
    if(owner.get()!=this||!a||a!=controller.authority_||!catalog)return false;
    std::lock_guard<std::mutex> operation(impl_->mutex);
    if(impl_->authority.lock()!=a)return false;
    const auto read=impl_->read();if(!impl_->samePrecedent(read)||!sameEntitlementPublication(read,proof))return false;
    std::lock_guard<std::mutex> lock(a->mutex);
    if(!Detail::entitlementImageCurrent(*a,proof)||a->entitlement->catalog->generation_!=proof.catalogGeneration||
        catalog->generation_<=proof.catalogGeneration)return false;
    if(a->entitlement->floorGeneration==std::numeric_limits<std::uint64_t>::max()) {
        a->alive=false;return false;
    }
    if(!Detail::advanceEntitlement(*a))return false;
    auto &runtime=*a->entitlement;runtime.catalog=std::move(catalog);++runtime.floorGeneration;
    runtime.publishedImage.reset();runtime.publishedReview={};
    a->provider.evidence=EvidenceState::Missing;a->provider.scope={};a->provider.accountScope={};return true;
}
bool WindowsConfigurationStore::facadeAvailable(){std::lock_guard<std::mutex> operation(impl_->mutex);auto a=impl_->authority.lock();if(!a||!impl_->current())return false;std::lock_guard<std::mutex> lock(a->mutex);return a->alive;}
CredentialState WindowsConfigurationStore::credentialStatus(){std::lock_guard<std::mutex> operation(impl_->mutex);auto a=impl_->authority.lock();if(!a)return CredentialState::Unavailable;auto read=impl_->read();{std::lock_guard<std::mutex> lock(a->mutex);if(!a->alive||a->failureLatched)return CredentialState::Unavailable;}if(read.state==StorageState::Uninitialized)return impl_->legacyPresent()?CredentialState::Unavailable:CredentialState::Absent;if(read.state==StorageState::Corrupt)return CredentialState::Corrupt;return read.record&&impl_->samePrecedent(read)?read.record->metadata.credential:CredentialState::Unavailable;}
Broker::GeneralReservation WindowsConfigurationStore::reserveGeneral(NetworkPermit &permit,const Digest256 &binding,const Digest256 &seal){
    using Broker::Failure;Broker::GeneralReservation result;
    if(!permit.current(ActivationStage::BeforeReserve,binding,seal))return {Failure::Unauthorized,false,0};
    std::unique_lock<std::mutex> operation(impl_->mutex);if(!permit.lease_||permit.lease_->authority.lock()!=impl_->authority.lock()||!impl_->current())return {Failure::Unauthorized,false,0};
    const auto credentialCurrent=[&](const ReadResult &r){return r.record&&impl_->samePrecedent(r)&&r.record->metadata.storeInstance==permit.lease_->image.snapshot.storeInstance&&r.record->metadata.credential==CredentialState::Stored&&r.record->secret.size()&&r.record->metadata.epochs.credential==permit.lease_->image.snapshot.epochs.credential;};
    auto credential=impl_->read();if(!credentialCurrent(credential))return result;
    const auto usage=impl_->root+L"\\usage.v1";const auto now=std::uint64_t(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());const auto day=now/86400;std::uint64_t oldDay=0,count=0,last=0;FileStamp previous;bool exists=false;
    {Handle file(CreateFileW(usage.c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        if(file){exists=true;Broker::SensitiveBytes bytes(32);LARGE_INTEGER size{};DWORD n=0;FileStamp after;if(!stamp(file.value,previous,false,impl_->identity,true)||!GetFileSizeEx(file.value,&size)||size.QuadPart!=32||!ReadFile(file.value,bytes.data(),32,&n,nullptr)||n!=32||!stamp(file.value,after,false,impl_->identity,true)||!sameFile(previous,after))return {Failure::Corrupt,false,0};
            const auto *d=bytes.data();if(std::memcmp(d,"GBAU",4)||d[4]!=1||d[5]||d[6]||d[7])return {Failure::Corrupt,false,0};const auto number=[&](unsigned p){std::uint64_t v=0;for(unsigned i=0;i<8;++i)v|=std::uint64_t(d[p+i])<<(8*i);return v;};oldDay=number(8);count=number(16);last=number(24);if(count>60||last/86400!=oldDay||now<last)return {Failure::RateLimited,false,0};
        }else {const DWORD error=GetLastError();if(error!=ERROR_FILE_NOT_FOUND)return {Failure::VaultUnavailable,false,error};}
    }
    if(oldDay!=day)count=0;
    const auto initialDispatch=impl_->lastDispatch;const auto tick=GetTickCount64();if(count>=60||(impl_->lastDispatch&&tick-impl_->lastDispatch<10000)||(last&&now<last+10))return {Failure::RateLimited,false,0};
    Broker::SensitiveBytes bytes(32);std::memcpy(bytes.data(),"GBAU",4);bytes.data()[4]=1;const auto put=[&](unsigned p,std::uint64_t v){for(unsigned i=0;i<8;++i)bytes.data()[p+i]=static_cast<unsigned char>(v>>(8*i));};put(8,day);put(16,count+1);put(24,now);
    Id128 nonce{};if(!Broker::randomId(nonce))return result;const char hex[]="0123456789abcdef";std::wstring pending=impl_->root+L"\\usage-";for(auto b:nonce){pending+=wchar_t(hex[b>>4]);pending+=wchar_t(hex[b&15]);}pending+=L".tmp";
    SECURITY_ATTRIBUTES sa{sizeof(sa),impl_->descriptor,FALSE};FileStamp temporary;Handle file(CreateFileW(pending.c_str(),GENERIC_WRITE|READ_CONTROL,0,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));DWORD written=0;
    if(!file){result.primaryError=GetLastError();return result;}bool ok=stamp(file.value,temporary,false,impl_->identity,true);if(ok){ok=WriteFile(file.value,bytes.data(),32,&written,nullptr)!=FALSE;if(!ok)result.primaryError=GetLastError();else if(written!=32){ok=false;result.primaryError=ERROR_WRITE_FAULT;}}if(ok){ok=FlushFileBuffers(file.value)!=FALSE;if(!ok)result.primaryError=GetLastError();}
    PublicationIdentity prepared;if(ok){ok=capturePublication(file.value,bytes,"LGA_GATEBOUNCER_USAGE_PUBLICATION_V1",impl_->identity,prepared);if(ok)temporary=prepared.file;}file.reset();
    if(!ok||!impl_->current()){impl_->cleanup(pending,temporary);return result;}
    if(exists){Handle old(CreateFileW(usage.c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));FileStamp checked;if(!old||!stamp(old.value,checked,false,impl_->identity,true)||!sameFile(previous,checked)){impl_->cleanup(pending,temporary);return result;}}
    operation.unlock();const bool authorized=permit.current(ActivationStage::BeforeReserve,binding,seal);operation.lock();if(!authorized||!impl_->current()){impl_->cleanup(pending,temporary);return {Failure::Unauthorized,false,0};}
    auto actualCredential=impl_->read();if(!credentialCurrent(actualCredential)||!sameFile(credential.file,actualCredential.file)||actualCredential.record->integrity!=credential.record->integrity||actualCredential.envelopeDigest!=credential.envelopeDigest){impl_->cleanup(pending,temporary);return {Failure::Unauthorized,false,0};}
    if(impl_->lastDispatch!=initialDispatch){impl_->cleanup(pending,temporary);return {Failure::RateLimited,false,0};}
    {Handle old(CreateFileW(usage.c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));FileStamp checked;const DWORD error=old?0:GetLastError();if(exists?(!old||!stamp(old.value,checked,false,impl_->identity,true)||!sameFile(previous,checked)):(old||error!=ERROR_FILE_NOT_FOUND)){impl_->cleanup(pending,temporary);return {Failure::Uncertain,false,error};}}
    const BOOL published=exists?ReplaceFileW(usage.c_str(),pending.c_str(),nullptr,0,nullptr,nullptr):MoveFileExW(pending.c_str(),usage.c_str(),MOVEFILE_WRITE_THROUGH);const DWORD primary=published?0:GetLastError();
    Handle observed(CreateFileW(usage.c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));FileStamp observedId;Broker::SensitiveBytes after(32);LARGE_INTEGER size{};DWORD n=0;
    FileStamp stable;result.committed=prepared.captured&&observed&&stamp(observed.value,observedId,false,impl_->identity,true)&&GetFileSizeEx(observed.value,&size)&&size.QuadPart==32&&ReadFile(observed.value,after.data(),32,&n,nullptr)&&n==32&&!std::memcmp(bytes.data(),after.data(),32)&&sameId(prepared.file,observedId)&&fileSize(prepared.file)==fileSize(observedId)&&prepared.bytesDigest==digest("LGA_GATEBOUNCER_USAGE_PUBLICATION_V1",after.data(),after.size())&&stamp(observed.value,stable,false,impl_->identity,true)&&sameFile(observedId,stable)&&impl_->current();
    result.primaryError=primary;result.failure=published&&result.committed?Failure::None:Failure::Uncertain;if(result.committed)impl_->lastDispatch=tick;impl_->cleanup(pending,temporary);operation.unlock();
    if(!permit.current(ActivationStage::BeforeReserve,binding,seal)&&result.failure==Failure::None)result.failure=Failure::Stale;
    return result;
}
}
