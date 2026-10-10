#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <winternl.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <stdexcept>
#include "OriginalBootstrapProtocol.hpp"
#include "../../../../common/token_ii_win.h"
namespace gb::original {
struct Handle {
    HANDLE h=nullptr;
    Handle()=default;explicit Handle(HANDLE v):h(v==INVALID_HANDLE_VALUE?nullptr:v){}
    Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
    Handle(Handle&& v)noexcept:h(v.h){v.h=nullptr;}
    Handle& operator=(Handle&& v)noexcept {if(h)CloseHandle(h);h=v.h;v.h=nullptr;return *this;}
    ~Handle(){if(h)CloseHandle(h);}
    bool Close(){if(!h)return true;if(!CloseHandle(h))return false;h=nullptr;return true;}
};
inline std::uint64_t Created(HANDLE p) {FILETIME a{},b{},c{},d{};return GetProcessTimes(p,&a,&b,&c,&d)?(static_cast<std::uint64_t>(a.dwHighDateTime)<<32)|a.dwLowDateTime:0;}
inline DWORD ParentPid(HANDLE p) {
    const auto query=reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess"));
    PROCESS_BASIC_INFORMATION b{};ULONG n=0;
    return query&&query(p,ProcessBasicInformation,&b,sizeof(b),&n)==0&&n==sizeof(b)?static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(b.Reserved3)):0;
}
inline bool Token(HANDLE process,native::TokenEvidence& value) {HANDLE h=nullptr;if(!OpenProcessToken(process,TOKEN_QUERY,&h))return false;Handle token(h);return native::tokenEvidence(h,value);}
inline bool EqualToken(const native::TokenEvidence&a,const native::TokenEvidence&b) {
    return native::equalSidBytes(a.account,b.account)&&native::equalSidBytes(a.logon,b.logon)&&a.session==b.session&&a.integrity==b.integrity&&a.elevated==b.elevated&&a.uiAccess==b.uiAccess;
}
inline std::wstring Image(HANDLE p) {std::array<wchar_t,32768>b{};DWORD n=static_cast<DWORD>(b.size());return QueryFullProcessImageNameW(p,0,b.data(),&n)?std::wstring(b.data(),n):std::wstring();}
inline bool InOriginalBase(HANDLE process,DWORD pid) {
    BOOL in=FALSE;if(!IsProcessInJob(process,nullptr,&in)||!in)return false;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit{};JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
    if(!QueryInformationJobObject(nullptr,JobObjectExtendedLimitInformation,&limit,sizeof(limit),nullptr)||
       !QueryInformationJobObject(nullptr,JobObjectBasicUIRestrictions,&ui,sizeof(ui),nullptr)||
       limit.BasicLimitInformation.LimitFlags!=(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION)||ui.UIRestrictionsClass!=0xd8)return false;
    alignas(JOBOBJECT_BASIC_PROCESS_ID_LIST)std::array<BYTE,65536> list{};DWORD size=0;
    if(!QueryInformationJobObject(nullptr,JobObjectBasicProcessIdList,list.data(),static_cast<DWORD>(list.size()),&size))return false;
    const auto* ids=reinterpret_cast<const JOBOBJECT_BASIC_PROCESS_ID_LIST*>(list.data());
    if(ids->NumberOfAssignedProcesses!=ids->NumberOfProcessIdsInList||ids->NumberOfProcessIdsInList>4096)return false;
    for(DWORD i=0;i<ids->NumberOfProcessIdsInList;++i)if(ids->ProcessIdList[i]==pid)return true;
    return false;
}
inline std::wstring Desktop(DWORD thread) {std::array<wchar_t,512>b{};DWORD size=0;HDESK d=GetThreadDesktop(thread);return d&&GetUserObjectInformationW(d,UOI_NAME,b.data(),sizeof(b),&size)?std::wstring(b.data()):std::wstring();}
inline std::wstring Quote(const std::wstring&s) {
    std::wstring out=L"\"";unsigned slash=0;
    for(wchar_t c:s){if(c==L'\\'){++slash;continue;}if(c==L'\"'){out.append(slash*2+1,L'\\');out+=c;slash=0;continue;}out.append(slash,L'\\');slash=0;out+=c;}
    out.append(slash*2,L'\\');out+=L'\"';return out;
}
inline bool SameFile(const BY_HANDLE_FILE_INFORMATION&a,const BY_HANDLE_FILE_INFORMATION&b,bool mutableLeaf=false) {
    return a.dwVolumeSerialNumber==b.dwVolumeSerialNumber&&a.nFileIndexHigh==b.nFileIndexHigh&&a.nFileIndexLow==b.nFileIndexLow&&a.dwFileAttributes==b.dwFileAttributes&&
        (mutableLeaf||(a.nFileSizeHigh==b.nFileSizeHigh&&a.nFileSizeLow==b.nFileSizeLow&&CompareFileTime(&a.ftLastWriteTime,&b.ftLastWriteTime)==0));
}
// Cada enlace se vuelve a abrir y comparar contra su padre retenido; sin reparse ni DELETE share.
class File final {
public:
    bool Open(const std::wstring& path,bool directory=false,bool mutableLeaf=false,bool writerBacked=false) {
        if(path.size()<4||path[1]!=L':'||(path[2]!=L'\\'&&path[2]!=L'/')||path.find(L"..")!=std::wstring::npos)return false;
        path_=std::filesystem::path(path).lexically_normal().wstring();mutable_=mutableLeaf;writerBacked_=writerBacked;
        std::filesystem::path part=std::filesystem::path(path_).root_path();
        if(!Add(part.wstring(),true,false))return false;
        for(const auto& component:std::filesystem::path(path_).relative_path()) {
            part/=component;const bool last=part==std::filesystem::path(path_);
            if(!Add(part.wstring(),!last||directory,last&&(mutableLeaf||writerBacked)))return false;
        }
        return nodes_.size()>1&&Current();
    }
    bool Current()const {
        for(std::size_t i=0;i<nodes_.size();++i) {
            BY_HANDLE_FILE_INFORMATION held{},now{};
            if(!GetFileInformationByHandle(nodes_[i].handle.h,&held)||!SameFile(nodes_[i].id,held,mutable_&&i+1==nodes_.size()))return false;
            Handle again(CreateFileW(nodes_[i].path.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|((mutable_||writerBacked_)&&i+1==nodes_.size()?FILE_SHARE_WRITE:0),nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr));
            if(!again.h||!GetFileInformationByHandle(again.h,&now)||now.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT||!SameFile(nodes_[i].id,now,mutable_&&i+1==nodes_.size()))return false;
        }return true;
    }
    HANDLE Raw()const{return nodes_.empty()?nullptr:nodes_.back().handle.h;}
    const std::wstring& Path()const{return path_;}
    bool RetainWriter(HANDLE writer) {
        BY_HANDLE_FILE_INFORMATION w{};if(!Current()||!GetFileInformationByHandle(writer,&w)||!SameFile(nodes_.back().id,w))return false;
        HANDLE duplicate=nullptr;if(!DuplicateHandle(GetCurrentProcess(),writer,GetCurrentProcess(),&duplicate,GENERIC_READ,FALSE,0))return false;
        nodes_.back().handle=Handle(duplicate);return Current();
    }
    std::uint64_t Size()const {LARGE_INTEGER n{};return GetFileSizeEx(Raw(),&n)&&n.QuadPart>=0?static_cast<std::uint64_t>(n.QuadPart):UINT64_MAX;}
    bool Read(Bytes& bytes,std::size_t cap)const {
        if(!Current()||Size()>cap)return false;LARGE_INTEGER zero{};if(!SetFilePointerEx(Raw(),zero,nullptr,FILE_BEGIN))return false;
        bytes.resize(static_cast<std::size_t>(Size()));std::size_t at=0;
        while(at<bytes.size()){DWORD n=0;if(!ReadFile(Raw(),bytes.data()+at,static_cast<DWORD>(std::min<std::size_t>(65536,bytes.size()-at)),&n,nullptr)||!n)return false;at+=n;}return Current();
    }
    bool Hash(const wchar_t* algorithm,const std::string& expected,const std::function<bool()>& fresh)const {
        if(!Current()||!fresh())return false;BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;
        if(BCryptOpenAlgorithmProvider(&alg,algorithm,MS_PRIMITIVE_PROVIDER,0)!=0)return false;
        DWORD size=0,n=0;bool okay=BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,reinterpret_cast<BYTE*>(&size),sizeof(size),&n,0)==0;
        Bytes object(size),digest(expected.size()/2);okay=okay&&BCryptCreateHash(alg,&hash,object.data(),size,nullptr,0,0)==0;
        LARGE_INTEGER zero{};okay=okay&&SetFilePointerEx(Raw(),zero,nullptr,FILE_BEGIN);std::array<BYTE,65536>b{};
        while(okay){DWORD count=0;okay=fresh()&&ReadFile(Raw(),b.data(),static_cast<DWORD>(b.size()),&count,nullptr)&&fresh();if(!okay||!count)break;okay=BCryptHashData(hash,b.data(),count,0)==0;}
        okay=okay&&BCryptFinishHash(hash,digest.data(),static_cast<ULONG>(digest.size()),0)==0;
        constexpr char hex[]="0123456789abcdef";std::string actual;for(auto v:digest){actual+=hex[v>>4];actual+=hex[v&15];}
        if(hash)BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(alg,0);return okay&&actual==expected&&Current()&&fresh();
    }
    bool Same(HANDLE other)const {BY_HANDLE_FILE_INFORMATION a{},b{};return GetFileInformationByHandle(Raw(),&a)&&GetFileInformationByHandle(other,&b)&&SameFile(a,b,true);}
    bool Close(){bool okay=true;for(auto i=nodes_.rbegin();i!=nodes_.rend();++i)okay=i->handle.Close()&&okay;if(okay)nodes_.clear();return okay;}
private:
    struct Node {Handle handle;BY_HANDLE_FILE_INFORMATION id{};std::wstring path;};std::vector<Node>nodes_;std::wstring path_;bool mutable_=false,writerBacked_=false;
    bool Add(const std::wstring&p,bool dir,bool mutableLeaf) {
        Node n;n.path=p;n.handle=Handle(CreateFileW(p.c_str(),GENERIC_READ,FILE_SHARE_READ|(mutableLeaf?FILE_SHARE_WRITE:0),nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|(dir?FILE_FLAG_BACKUP_SEMANTICS:0),nullptr));
        if(!n.handle.h||!GetFileInformationByHandle(n.handle.h,&n.id)||n.id.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT||static_cast<bool>(n.id.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=dir)return false;
        nodes_.push_back(std::move(n));return true;
    }
};
struct Child final {
    Handle process,thread;DWORD pid=0,threadId=0;std::uint64_t created=0;std::wstring image,desktop;native::TokenEvidence token;bool resumed=false;
    bool Current()const {
        native::TokenEvidence now;
        return process.h&&Created(process.h)==created&&WaitForSingleObject(process.h,0)==WAIT_TIMEOUT&&GetProcessId(process.h)==pid&&Image(process.h)==image&&
            ParentPid(process.h)==GetCurrentProcessId()&&Token(process.h,now)&&EqualToken(token,now)&&InOriginalBase(process.h,pid)&&Desktop(threadId)==desktop;
    }
    bool Start(const File& exe,const std::vector<std::wstring>&arguments,const std::wstring&cwd,const std::array<HANDLE,3>&stdio,const std::function<bool()>&fresh) {
        if(!exe.Current()||!fresh()||process.h)return false;
        image=exe.Path();desktop=Desktop(GetCurrentThreadId());if(desktop.empty()||desktop==L"Default")return false;
        std::wstring command=Quote(image);for(const auto&a:arguments){command+=L' ';command+=Quote(a);}
        SIZE_T size=0;InitializeProcThreadAttributeList(nullptr,1,0,&size);Bytes storage(size);auto* list=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        if(!InitializeProcThreadAttributeList(list,1,0,&size))return false;
        bool okay=UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,const_cast<HANDLE*>(stdio.data()),sizeof(stdio),nullptr,nullptr)!=FALSE;
        STARTUPINFOEXW start{};start.StartupInfo.cb=sizeof(start);start.StartupInfo.dwFlags=STARTF_USESTDHANDLES;start.StartupInfo.lpDesktop=desktop.data();
        start.StartupInfo.hStdInput=stdio[0];start.StartupInfo.hStdOutput=stdio[1];start.StartupInfo.hStdError=stdio[2];start.lpAttributeList=list;
        PROCESS_INFORMATION pi{};const wchar_t env[]=L"SystemRoot=C:\\Windows\0PATH=C:\\Windows\\System32\0LANG=C\0\0";
        okay=okay&&fresh()&&CreateProcessW(image.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT|CREATE_UNICODE_ENVIRONMENT|CREATE_NO_WINDOW,const_cast<wchar_t*>(env),cwd.c_str(),&start.StartupInfo,&pi)!=FALSE;
        DeleteProcThreadAttributeList(list);if(!okay)return false;
        process=Handle(pi.hProcess);thread=Handle(pi.hThread);pid=pi.dwProcessId;threadId=pi.dwThreadId;created=Created(process.h);
        native::TokenEvidence parentToken;
        if(!created||!Token(process.h,token)||!Token(GetCurrentProcess(),parentToken)||!EqualToken(token,parentToken)||!Current()||!exe.Current()||!fresh())return false;
        resumed=true;if(ResumeThread(thread.h)!=1||!fresh())return false;DWORD terminal=0;return Current()||Terminal(terminal);
    }
    bool Terminal(DWORD& code)const {return process.h&&Created(process.h)==created&&WaitForSingleObject(process.h,0)==WAIT_OBJECT_0&&GetExitCodeProcess(process.h,&code)&&code!=STILL_ACTIVE;}
    bool Close() {if(process.h&&WaitForSingleObject(process.h,0)==WAIT_TIMEOUT&&!TerminateProcess(process.h,5))return false;if(process.h&&WaitForSingleObject(process.h,0)!=WAIT_OBJECT_0)return false;return thread.Close()&&process.Close();}
};
inline std::wstring PipeSecurity() {
    native::TokenEvidence t;if(!Token(GetCurrentProcess(),t)||t.integrity<SECURITY_MANDATORY_MEDIUM_RID||t.integrity>SECURITY_MANDATORY_HIGH_RID||t.uiAccess)return {};
    const auto sid=native::sidString(t.account);return L"O:"+sid+L"G:"+sid+L"D:P(D;;GA;;;NU)(D;;GA;;;AN)(A;;GA;;;"+sid+L")S:P(ML;;NW;;;S-1-16-"+std::to_wstring(t.integrity)+L")";
}
}
