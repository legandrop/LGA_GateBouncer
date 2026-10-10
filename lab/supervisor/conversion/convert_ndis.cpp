#ifndef NOMINMAX
#define NOMINMAX
#endif
// Conversor acotado del perfil guest P3.
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <string>
#include <vector>
namespace gb {
constexpr std::uint64_t FileCap = 8388608, Epoch = 116444736000000000;
enum class ConvertState { Ok, Cancelled, BudgetExceeded, IoIncomplete, Unsupported, Invalid };
struct Shape { std::wstring name; unsigned type, flags, count, lengthIndex; };
bool fragment_schema(const std::vector<Shape>& properties) {
    const std::array<std::wstring,4> names = {L"MiniportIfIndex", L"LowerIfIndex", L"FragmentSize", L"Fragment"};
    if (properties.size() != names.size()) return false;
    for (unsigned i = 0; i < names.size(); ++i) {
        const auto& p = properties[i];
        if (p.name != names[i] || p.count != 1 || p.type != (i == 3 ? 14u : 8u) ||
            p.flags != (i == 3 ? 2u : 0u) || (i == 3 && p.lengthIndex != 2)) return false;
    }
    return true;
}
std::uint16_t be16(const std::vector<std::uint8_t>& v, std::size_t p) {
    return static_cast<std::uint16_t>((v[p] << 8) | v[p + 1]);
}
// Sólo integridad de bytes L3, nunca longitud original del paquete NDIS ni atribución.
bool l3_complete(const std::vector<std::uint8_t>& v) {
    if (v.size() < 34 || v.size() > 1536) return false;
    const auto type = be16(v,12);
    std::size_t end = 0;
    if (type == 0x0800) {
        const auto ihl = (v[14] & 15u) * 4u;
        const auto len = be16(v,16);
        if ((v[14] >> 4) != 4 || ihl < 20 || len < ihl || len > 1500 ||
            (be16(v,20) & 0x3fff) != 0) return false;
        end = 14 + len;
    } else if (type == 0x86dd) {
        if (v.size() < 54 || (v[14] >> 4) != 6 || be16(v,18) == 0 ||
            be16(v,18) > 1460 || v[20] == 44) return false;
        end = 54 + be16(v,18);
        if(end>v.size()) return false;
        unsigned next=v[20], depth=0;
        std::size_t at=54;
        while(next==0 || next==43 || next==60 || next==51 || next==44) {
            if(++depth>8 || next==44 || at+2>end) return false;
            const auto length=next==51?(v[at+1]+2u)*4u:(v[at+1]+1u)*8u;
            if(length<8 || length>end-at) return false;
            next=v[at]; at+=length;
        }
        if(next==50 || next==59) return false;
    } else return false;
    return end == v.size() || (end <= 60 && v.size() == 60);
}
bool unix_ticks(std::int64_t normalized, std::uint64_t& ticks) {
    if (normalized < 0 || static_cast<std::uint64_t>(normalized) < Epoch) return false;
    ticks = static_cast<std::uint64_t>(normalized) - Epoch;
    return true;
}
bool fragment_scope(unsigned id, unsigned version, std::uint64_t keyword,
                    unsigned mini, unsigned lower, unsigned own, unsigned length,
                    std::int64_t timestamp, std::int64_t start, std::int64_t end) {
    const bool send=(keyword&0x100000000)!=0, receive=(keyword&0x200000000)!=0;
    return id==1001 && version==0 && (keyword&0xc0000000)==0xc0000000 &&
        !(keyword&(0x10000|0x200)) && send!=receive && own!=0 && mini==own && lower==own &&
        length>=34 && length<=1536 && timestamp>=start && timestamp<=end;
}
void u16(std::vector<std::uint8_t>& v, std::uint16_t n) {
    v.push_back(static_cast<std::uint8_t>(n & 255)); v.push_back(static_cast<std::uint8_t>(n >> 8));
}
void u32(std::vector<std::uint8_t>& v, std::uint32_t n) {
    for (unsigned s = 0; s < 32; s += 8) v.push_back(static_cast<std::uint8_t>((n >> s) & 255));
}
struct PcapWriter {
    std::uint64_t used = 0, committed = 0, cap;
    std::uint32_t packets = 0;
    ConvertState state = ConvertState::Ok;
    bool initialized = false, exactIo = true;
    std::function<bool()> live;
    std::function<bool(const std::vector<std::uint8_t>&)> write;
    PcapWriter(std::function<bool()> guard,
               std::function<bool(const std::vector<std::uint8_t>&)> sink,
               std::uint64_t budget = FileCap) : cap(budget), live(guard), write(sink) {}
    bool block(std::uint32_t type, const std::vector<std::uint8_t>& body) {
        if (state != ConvertState::Ok) return false;
        if (!live()) { state = ConvertState::Cancelled; return false; }
        const auto size = body.size() + 12;
        if (cap > FileCap || used > cap || size > cap - used || (body.size() & 3)) {
            state = ConvertState::BudgetExceeded; return false;
        }
        std::vector<std::uint8_t> bytes;
        u32(bytes,type); u32(bytes,static_cast<std::uint32_t>(size));
        bytes.insert(bytes.end(),body.begin(),body.end()); u32(bytes,static_cast<std::uint32_t>(size));
        used += size; // Reserva previa: error o escritura parcial nunca permiten reutilizarla.
        if (!write(bytes)) { exactIo=false; state = ConvertState::IoIncomplete; return false; }
        committed+=size;
        if (!live()) { state = ConvertState::Cancelled; return false; }
        return true;
    }
    bool begin() {
        if (initialized || state != ConvertState::Ok) return false;
        std::vector<std::uint8_t> shb;
        u32(shb,0x1a2b3c4d); u16(shb,1); u16(shb,0);
        u32(shb,0xffffffff); u32(shb,0xffffffff);
        if (!block(0x0a0d0d0a,shb)) return false;
        std::vector<std::uint8_t> idb;
        u16(idb,1); u16(idb,0); u32(idb,1536);
        const std::string comment = "NDIS original length unknown";
        u16(idb,1); u16(idb,28); idb.insert(idb.end(),comment.begin(),comment.end());
        u16(idb,9); u16(idb,1); u32(idb,7); u32(idb,0);
        initialized = block(1,idb);
        return initialized;
    }
    bool packet(const std::vector<std::uint8_t>& frame, std::int64_t timestamp, unsigned direction) {
        std::uint64_t ticks = 0;
        if (!initialized || state != ConvertState::Ok) return false;
        if (packets >= 25000 || !unix_ticks(timestamp,ticks) || !l3_complete(frame) ||
            (direction != 1 && direction != 2)) { state = ConvertState::Unsupported; return false; }
        std::vector<std::uint8_t> body;
        u32(body,0); u32(body,static_cast<std::uint32_t>(ticks >> 32)); u32(body,static_cast<std::uint32_t>(ticks & 0xffffffff));
        u32(body,static_cast<std::uint32_t>(frame.size())); u32(body,static_cast<std::uint32_t>(frame.size())); // Representación mínima; origen Unknown.
        body.insert(body.end(),frame.begin(),frame.end());
        while (body.size() & 3) body.push_back(0);
        u16(body,2); u16(body,4); u32(body,direction); u32(body,0);
        if (!block(6,body)) return false;
        ++packets; return true;
    }
};
}


#define WIN32_LEAN_AND_MEAN
#include "convert_ndis.hpp"
#include "P3Transfer.hpp"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <algorithm>
namespace gb {
const GUID NdisProvider = {0x2ed6006e,0x4729,0x4609,{0xb4,0x23,0x3e,0xe7,0xbc,0xd6,0x78,0xef}};
struct NativeConversion {
    OwnedConversion& owned;
    ConversionReport report;
    ULONGLONG started = GetTickCount64();
    TRACEHANDLE trace = INVALID_PROCESSTRACE_HANDLE;
    PcapWriter writer;
    NativeConversion(OwnedConversion& c) : owned(c), writer(
        [this] { return live(); }, [this](const auto& bytes) {
            DWORD count = 0;
            return WriteFile(owned.output_,bytes.data(),static_cast<DWORD>(bytes.size()),&count,nullptr) &&
                   count == bytes.size();
        }) {}
    ~NativeConversion() { if(trace!=INVALID_PROCESSTRACE_HANDLE) CloseTrace(trace); }
    bool live() const {
        return WaitForSingleObject(owned.cancel_,0) == WAIT_TIMEOUT &&
               GetTickCount64() - started < 30000;
    }
    bool files() const {
        BY_HANDLE_FILE_INFORMATION in{}, out{};
        if (GetFileType(owned.input_) != FILE_TYPE_DISK || GetFileType(owned.output_) != FILE_TYPE_DISK ||
            !GetFileInformationByHandle(owned.input_,&in) || !GetFileInformationByHandle(owned.output_,&out)) return false;
        const auto size = (static_cast<std::uint64_t>(in.nFileSizeHigh) << 32) | in.nFileSizeLow;
        return in.nNumberOfLinks == 1 && out.nNumberOfLinks == 1 && size > 0 && size <= FileCap &&
            !(in.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
            !(out.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
            in.dwVolumeSerialNumber == owned.identity_.dwVolumeSerialNumber &&
            in.nFileIndexHigh == owned.identity_.nFileIndexHigh && in.nFileIndexLow == owned.identity_.nFileIndexLow &&
            in.nFileSizeHigh == owned.identity_.nFileSizeHigh && in.nFileSizeLow == owned.identity_.nFileSizeLow &&
            in.ftLastWriteTime.dwHighDateTime == owned.identity_.ftLastWriteTime.dwHighDateTime &&
            in.ftLastWriteTime.dwLowDateTime == owned.identity_.ftLastWriteTime.dwLowDateTime;
    }
    bool job() const {
        BOOL inside = FALSE;
        // No heredar HANDLE Job: el padre debe ser su único tenedor para kill-on-close.
        return IsProcessInJob(GetCurrentProcess(), nullptr, &inside) && inside && P3LimitsCurrent(nullptr);
    }
    std::wstring path(const wchar_t* filename) const {
        return L"C:\\GateBouncerLab\\captures\\" + owned.run_ + L"\\" + filename;
    }
    bool fixed_paths() const {
        if (owned.run_.size() != 36 || owned.interface_ == 0 || owned.start_ < static_cast<std::int64_t>(Epoch) ||
            owned.end_ <= owned.start_ || owned.end_ - owned.start_ > 600000000) return false;
        for (unsigned i=0; i<36; ++i) {
            const auto ch=owned.run_[i];
            if ((i==8 || i==13 || i==18 || i==23) ? ch!=L'-' :
                !((ch>=L'0' && ch<=L'9') || (ch>=L'a' && ch<=L'f'))) return false;
        }
        wchar_t input[260]{}, output[260]{};
        const auto a=GetFinalPathNameByHandleW(owned.input_,input,260,FILE_NAME_NORMALIZED);
        const auto b=GetFinalPathNameByHandleW(owned.output_,output,260,FILE_NAME_NORMALIZED);
        return a && a<260 && b && b<260 && std::wstring(input)==L"\\\\?\\"+path(L"capture.etl") &&
               std::wstring(output)==L"\\\\?\\"+path(L"capture.pcapng");
    }
    bool property(EVENT_RECORD* ev, const wchar_t* name, void* out, ULONG size) {
        PROPERTY_DATA_DESCRIPTOR d{};
        d.PropertyName=reinterpret_cast<ULONGLONG>(name); d.ArrayIndex=ULONG_MAX;
        ULONG actual=0;
        return TdhGetPropertySize(ev,0,nullptr,1,&d,&actual)==ERROR_SUCCESS && actual==size &&
               TdhGetProperty(ev,0,nullptr,1,&d,size,static_cast<BYTE*>(out))==ERROR_SUCCESS;
    }
    bool schema(EVENT_RECORD* ev) {
        ULONG size=0;
        if (TdhGetEventInformation(ev,0,nullptr,nullptr,&size)!=ERROR_INSUFFICIENT_BUFFER ||
            size<sizeof(TRACE_EVENT_INFO) || size>65536) return false;
        std::vector<std::uint64_t> storage((size+7)/8);
        auto* info=reinterpret_cast<TRACE_EVENT_INFO*>(storage.data());
        if (TdhGetEventInformation(ev,0,nullptr,info,&size)!=ERROR_SUCCESS || size>storage.size()*8 ||
            info->DecodingSource!=DecodingSourceXMLFile || info->PropertyCount!=4 || info->TopLevelPropertyCount!=4 ||
            size<offsetof(TRACE_EVENT_INFO,EventPropertyInfoArray)+4*sizeof(EVENT_PROPERTY_INFO)) return false;
        std::vector<Shape> shapes;
        const auto* bytes=reinterpret_cast<const BYTE*>(info);
        for(unsigned i=0;i<4;++i) {
            const auto& p=info->EventPropertyInfoArray[i];
            if ((p.NameOffset&1) || p.NameOffset>=size) return false;
            std::wstring name;
            for(ULONG at=p.NameOffset; at+2<=size && name.size()<=64; at+=2) {
                wchar_t ch=0; std::memcpy(&ch,bytes+at,2);
                if(!ch) break;
                name.push_back(ch);
            }
            if(name.size()>64 || p.NameOffset+(name.size()+1)*2>size) return false;
            shapes.push_back({name,p.nonStructType.InType,static_cast<unsigned>(p.Flags),p.count,p.lengthPropertyIndex});
        }
        return fragment_schema(shapes);
    }
    void event(EVENT_RECORD* ev) {
        if (writer.state!=ConvertState::Ok) return;
        if (!live()) { writer.state=ConvertState::Cancelled; return; }
        if (++report.records>25000) { writer.state=ConvertState::BudgetExceeded; return; }
        if (!IsEqualGUID(ev->EventHeader.ProviderId,NdisProvider)) { ++report.otherProviderRecords; return; }
        const auto& desc=ev->EventHeader.EventDescriptor;
        const auto timestamp=ev->EventHeader.TimeStamp.QuadPart;
        if (desc.Id!=1001 || desc.Version!=0 || (desc.Keyword&0xc0000000)!=0xc0000000 ||
            (desc.Keyword&(0x10000|0x200)) || !schema(ev)) { writer.state=ConvertState::Unsupported; return; }
        const bool send=(desc.Keyword&0x100000000)!=0, receive=(desc.Keyword&0x200000000)!=0;
        ULONG mini=0, lower=0, length=0;
        if(send==receive || !property(ev,L"MiniportIfIndex",&mini,4) ||
           !property(ev,L"LowerIfIndex",&lower,4) || !property(ev,L"FragmentSize",&length,4) ||
           !fragment_scope(desc.Id,desc.Version,desc.Keyword,mini,lower,owned.interface_,length,
                           timestamp,owned.start_,owned.end_)) {
            writer.state=ConvertState::Unsupported; return;
        }
        std::vector<std::uint8_t> frame(length);
        if(!property(ev,L"Fragment",frame.data(),length)) { writer.state=ConvertState::Unsupported; return; }
        writer.packet(frame,timestamp,send?2:1);
    }
    static void WINAPI callback(EVENT_RECORD* ev) noexcept {
        auto* self=static_cast<NativeConversion*>(ev->UserContext);
        try { self->event(ev); }
        catch(...) { self->writer.state=ConvertState::Invalid; }
    }
    static ULONG WINAPI buffer(EVENT_TRACE_LOGFILEW* log) noexcept {
        auto* self=static_cast<NativeConversion*>(log->Context);
        if(!self->live()) self->writer.state=ConvertState::Cancelled;
        return self->writer.state==ConvertState::Ok;
    }
    ConversionReport run() {
        LARGE_INTEGER outputSize{};
        if(!live() || !files() || !fixed_paths() || !job() ||
           !GetFileSizeEx(owned.output_,&outputSize) || outputSize.QuadPart!=0) return report;
        auto name=path(L"capture.etl");
        EVENT_TRACE_LOGFILEW log{};
        log.LogFileName=name.data(); log.ProcessTraceMode=PROCESS_TRACE_MODE_EVENT_RECORD;
        log.EventRecordCallback=callback; log.BufferCallback=buffer; log.Context=this;
        trace=OpenTraceW(&log);
        if(trace==INVALID_PROCESSTRACE_HANDLE) { report.outcome="OpenTraceFailed"; return report; }
        report.nativeHeaderAvailable=true;
        report.nativeEventsLost=log.LogfileHeader.EventsLost; report.nativeBuffersLost=log.LogfileHeader.BuffersLost;
        report.nativeMode=log.LogfileHeader.LogFileMode;
        if(report.nativeEventsLost.value()!=0 || report.nativeBuffersLost.value()!=0 ||
           (report.nativeMode.value()&(EVENT_TRACE_FILE_MODE_CIRCULAR|EVENT_TRACE_FILE_MODE_NEWFILE)))
            writer.state=ConvertState::Invalid;
        ULONG process=ERROR_INVALID_DATA;
        if(writer.state==ConvertState::Ok && writer.begin()) process=ProcessTrace(&trace,1,nullptr,nullptr);
        const auto closed=CloseTrace(trace); trace=INVALID_PROCESSTRACE_HANDLE;
        report.reservedBytes=writer.used;
        if(writer.exactIo) report.emittedBytes=writer.committed;
        report.packets=writer.packets;
        if(writer.state==ConvertState::Ok && process==ERROR_SUCCESS && closed==ERROR_SUCCESS &&
           live() && files() && FlushFileBuffers(owned.output_) && live()) report.outcome="ConvertedOriginalLengthUnknown";
        else report.outcome=writer.state==ConvertState::Cancelled?"CancelledIncomplete":
            writer.state==ConvertState::BudgetExceeded?"BudgetExceededIncomplete":
            writer.state==ConvertState::Unsupported?"UnsupportedProfile":"ConversionIncomplete";
        return report;
    }
};
ConversionReport ConvertOwnedEtl(OwnedConversion& owned) noexcept {
    try { NativeConversion conversion(owned); return conversion.run(); }
    catch(...) { ConversionReport result; result.outcome="ConversionExceptionIncomplete"; return result; }
}
}
