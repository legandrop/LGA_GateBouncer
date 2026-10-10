#define NDIS630 1
#pragma warning(push)
#pragma warning(disable: 4201 4324)
#include <ntifs.h>
#include <ndis.h>
#include <fwpsk.h>
#include <initguid.h>
#include <fwpmk.h>
#include <wdmsec.h>
#pragma warning(pop)
#include "../common/classifier_protocol.h"
#define GB_TAG 'cBbG'
#define GB_MAX64 (~(UINT64)0)
#define GB_QUERY_PROCESS 0x1000
#define GB_PENDING_TICKS (120000ull*10000ull)
#define GB_CALLOUT_COUNT 10u
typedef struct GB_ENTRY {
    GB_CLASSIFIER_RECORD record;
    PEPROCESS process;
    PACCESS_TOKEN token;
    HANDLE completion;
    GB_SCOPE_RECEIPT receipt;
    GB_CANCEL_RECEIPT cancel;
    UINT64 pendingDeadline, parent;
    BOOLEAN delivered, revoked, closed, associated, completing, consumed, deadFlow;
    BOOLEAN cancelPin, futureRetired;
} GB_ENTRY;
typedef struct GB_TUPLE {
    UINT32 compartment;
    UINT16 localPort, remotePort;
    UCHAR family, local[16], remote[16];
} GB_TUPLE;
static EX_PUSH_LOCK gbControl;
static KSPIN_LOCK gbLock;
static GB_ENTRY *gbEntries[GB_CLASSIFIER_CAPACITY];
static UINT32 gbCalloutIds[GB_CALLOUT_COUNT];
static UINT64 gbSession, gbSequence, gbLoss;
static PFILE_OBJECT gbFile;
static PEPROCESS gbOwner;
static PDEVICE_OBJECT gbDevice;
static HANDLE gbEngine;
static BOOLEAN gbStarted, gbFault;
static KTIMER gbTimer;
static KDPC gbDpc;
static WORK_QUEUE_ITEM gbWork;
static volatile LONG gbQueued;
static UNICODE_STRING gbLink=RTL_CONSTANT_STRING(L"\\DosDevices\\LgaGateBouncerClassifier");
static NTSTATUS startClassifier(void);
static void controlEnter(void) { KeEnterCriticalRegion(); ExAcquirePushLockExclusive(&gbControl); }
static void controlLeave(void) { ExReleasePushLockExclusive(&gbControl); KeLeaveCriticalRegion(); }
static void block(FWPS_CLASSIFY_OUT0 *out) {
    // Veto WFP permitido ante Permit ajeno aun sin ACTION_WRITE.
    if((out->rights & FWPS_RIGHT_ACTION_WRITE) || out->actionType==FWP_ACTION_PERMIT) {
        out->actionType=FWP_ACTION_BLOCK; out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}
static void permit(FWPS_CLASSIFY_OUT0 *out) {
    if(out->rights & FWPS_RIGHT_ACTION_WRITE) out->actionType=FWP_ACTION_PERMIT;
}
static GB_ENTRY *byCause(UINT64 session,UINT64 cause) {
    ULONG i; for(i=0;i<GB_CLASSIFIER_CAPACITY;++i)
        if(gbEntries[i] && gbEntries[i]->record.session==session && gbEntries[i]->record.cause==cause) return gbEntries[i];
    return NULL;
}
static BOOLEAN currentEntry(GB_ENTRY *e) {
    PACCESS_TOKEN fresh; BOOLEAN same;
    if(PsGetProcessExitStatus(e->process)!=STATUS_PENDING ||
       (UINT64)PsGetProcessCreateTimeQuadPart(e->process)!=e->record.created) return FALSE;
    fresh=PsReferencePrimaryToken(e->process); same=fresh==e->token;
    PsDereferencePrimaryToken(fresh); return same;
}
static BOOLEAN grantLive(GB_ENTRY *e,UINT64 now) {
    return gbFile && !gbFault && !e->revoked && e->record.session==gbSession && e->record.loss==gbLoss &&
        e->consumed && e->receipt.applied &&
        (e->receipt.decision.scope!=GB_SCOPE_DURATION || now<e->receipt.deadline);
}
static BOOLEAN live(GB_ENTRY *e,UINT64 now) {
    GB_ENTRY *parent=e->parent ? byCause(e->record.session,e->parent) : e;
    return !e->deadFlow && !e->closed && grantLive(e,now) && parent && grantLive(parent,now);
}
static BOOLEAN sameInstance(const GB_ENTRY *p,const GB_ENTRY *e) {
    return p->process==e->process && p->token==e->token && p->record.created==e->record.created &&
        p->record.appBytes==e->record.appBytes && p->record.userBytes==e->record.userBytes &&
        RtlCompareMemory(p->record.app,e->record.app,p->record.appBytes)==p->record.appBytes &&
        RtlCompareMemory(p->record.user,e->record.user,p->record.userBytes)==p->record.userBytes;
}
static GB_ENTRY *futureRoot(GB_ENTRY *e,UINT64 now,BOOLEAN *ambiguous) {
    GB_ENTRY *found=NULL; ULONG i; *ambiguous=FALSE;
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) {
        GB_ENTRY *p=gbEntries[i];
        if(!p || p->parent || p->futureRetired || !grantLive(p,now) ||
           (p->receipt.decision.scope!=GB_SCOPE_INSTANCE && p->receipt.decision.scope!=GB_SCOPE_DURATION) ||
           !sameInstance(p,e)) continue;
        if(found) *ambiguous=TRUE; else found=p;
    }
    return found;
}
static void retireFutureRoots(GB_ENTRY *e) {
    ULONG i;
    if(e->parent || !e->receipt.applied ||
       (e->receipt.decision.scope!=GB_SCOPE_INSTANCE && e->receipt.decision.scope!=GB_SCOPE_DURATION)) return;
    // Sólo cambia la selección de futuras initial; los flows previos conservan raíz/plazo.
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) {
        GB_ENTRY *p=gbEntries[i];
        if(!p || p==e || p->parent || !p->receipt.applied ||
           (p->receipt.decision.scope!=GB_SCOPE_INSTANCE && p->receipt.decision.scope!=GB_SCOPE_DURATION)) continue;
        if(p->record.session==e->record.session && p->record.loss==e->record.loss && sameInstance(p,e)) p->futureRetired=TRUE;
    }
    e->futureRetired=FALSE;
}
static void revoke(GB_ENTRY *e) {
    e->revoked=TRUE; e->receipt.current=0;
    e->receipt.state=e->closed ? GB_SCOPE_CLOSED : GB_SCOPE_REVOKED;
}
static void loss(void) {
    ULONG i; if(gbLoss!=GB_MAX64) ++gbLoss;
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) if(gbEntries[i]) revoke(gbEntries[i]);
}
static void freeEntry(GB_ENTRY *e) {
    PsDereferencePrimaryToken(e->token); ObDereferenceObject(e->process); ExFreePoolWithTag(e,GB_TAG);
}
static BOOLEAN serviceOwner(void) {
    PACCESS_TOKEN token=PsReferencePrimaryToken(PsGetCurrentProcess());
    PTOKEN_USER user=NULL; PTOKEN_GROUPS groups=NULL; BOOLEAN accepted=FALSE;
    SID_IDENTIFIER_AUTHORITY authority=SECURITY_NT_AUTHORITY;
    UCHAR storage[SECURITY_MAX_SID_SIZE]; PSID service=(PSID)storage; ULONG i;
    RtlInitializeSid(service,&authority,6); *RtlSubAuthoritySid(service,0)=SECURITY_SERVICE_ID_BASE_RID;
    *RtlSubAuthoritySid(service,1)=261359355; *RtlSubAuthoritySid(service,2)=3591545304;
    *RtlSubAuthoritySid(service,3)=103058424; *RtlSubAuthoritySid(service,4)=11622622; *RtlSubAuthoritySid(service,5)=265084995;
    if(NT_SUCCESS(SeQueryInformationToken(token,TokenUser,(PVOID *)&user)) && user &&
       RtlEqualSid(user->User.Sid,SeExports->SeLocalSystemSid) &&
       NT_SUCCESS(SeQueryInformationToken(token,TokenGroups,(PVOID *)&groups)) && groups)
        for(i=0;i<groups->GroupCount;++i)
            if((groups->Groups[i].Attributes & 4L) && !(groups->Groups[i].Attributes & 0x10L) &&
               RtlEqualSid(groups->Groups[i].Sid,service)) { accepted=TRUE; break; }
    if(user) ExFreePool(user);
    if(groups) ExFreePool(groups);
    PsDereferencePrimaryToken(token); return accepted;
}
static BOOLEAN tuple(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,GB_TUPLE *t) {
    ULONG la,ra,lp,rp,c; BOOLEAN packet,flow,closure; UINT32 compartment;
    if(!v || !m) return FALSE;
    packet=v->layerId==FWPS_LAYER_STREAM_PACKET_V4 || v->layerId==FWPS_LAYER_STREAM_PACKET_V6;
    flow=v->layerId==FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 || v->layerId==FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6;
    closure=v->layerId==FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4 || v->layerId==FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V6;
    RtlZeroMemory(t,sizeof(*t));
    t->family=(v->layerId==FWPS_LAYER_STREAM_PACKET_V4 || v->layerId==FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 ||
        v->layerId==FWPS_LAYER_ALE_AUTH_CONNECT_V4 || v->layerId==FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4) ? 4 : 6;
    if(packet) {
        la=0; ra=1; lp=2; rp=3;
        c=t->family==4 ? FWPS_FIELD_STREAM_PACKET_V4_COMPARTMENT_ID : FWPS_FIELD_STREAM_PACKET_V6_COMPARTMENT_ID;
    } else {
        la=2; ra=6; lp=4; rp=7;
        if(flow) c=t->family==4 ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_COMPARTMENT_ID : FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_COMPARTMENT_ID;
        else if(closure) c=t->family==4 ? FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_COMPARTMENT_ID : FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_COMPARTMENT_ID;
        else c=t->family==4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_COMPARTMENT_ID : FWPS_FIELD_ALE_AUTH_CONNECT_V6_COMPARTMENT_ID;
    }
    if(v->valueCount<=c || v->valueCount<=rp || v->incomingValue[c].value.type!=FWP_UINT32 ||
       v->incomingValue[lp].value.type!=FWP_UINT16 || v->incomingValue[rp].value.type!=FWP_UINT16) return FALSE;
    compartment=v->incomingValue[c].value.uint32;
    t->compartment=compartment; t->localPort=v->incomingValue[lp].value.uint16; t->remotePort=v->incomingValue[rp].value.uint16;
    if(t->family==4) {
        if(v->incomingValue[la].value.type!=FWP_UINT32 || v->incomingValue[ra].value.type!=FWP_UINT32) return FALSE;
        RtlCopyMemory(t->local,&v->incomingValue[la].value.uint32,4); RtlCopyMemory(t->remote,&v->incomingValue[ra].value.uint32,4);
    } else {
        if(v->incomingValue[la].value.type!=FWP_BYTE_ARRAY16_TYPE || v->incomingValue[ra].value.type!=FWP_BYTE_ARRAY16_TYPE ||
           !v->incomingValue[la].value.byteArray16 || !v->incomingValue[ra].value.byteArray16) return FALSE;
        RtlCopyMemory(t->local,v->incomingValue[la].value.byteArray16,16); RtlCopyMemory(t->remote,v->incomingValue[ra].value.byteArray16,16);
    }
    return TRUE;
}
static BOOLEAN sameTuple(const GB_ENTRY *e,const GB_TUPLE *t) {
    return e->record.family==t->family && e->record.compartment==t->compartment &&
        e->record.localPort==t->localPort && e->record.remotePort==t->remotePort &&
        RtlCompareMemory(e->record.localAddress,t->local,16)==16 && RtlCompareMemory(e->record.remoteAddress,t->remote,16)==16;
}
static GB_ENTRY *endpoint(const FWPS_INCOMING_METADATA_VALUES0 *m,const GB_TUPLE *t,BOOLEAN fieldCompartment,BOOLEAN closingCompletion,BOOLEAN *ambiguous) {
    GB_ENTRY *found=NULL; ULONG i; *ambiguous=FALSE;
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) {
        GB_ENTRY *e=gbEntries[i];
        if(!e || (e->closed && !(closingCompletion && e->completing)) || !sameTuple(e,t)) continue;
        if(!fieldCompartment && (!(m->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID) || m->compartmentId!=t->compartment)) {
            *ambiguous=TRUE; continue;
        }
        if(!(m->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) || !m->transportEndpointHandle) {
            *ambiguous=TRUE; continue;
        }
        if(e->record.endpoint!=m->transportEndpointHandle) continue;
        if(found) *ambiguous=TRUE; else found=e;
    }
    return found;
}
static void NTAPI processExit(PEPROCESS process,HANDLE pid,PPS_CREATE_NOTIFY_INFO info) {
    KIRQL irql; ULONG i; UNREFERENCED_PARAMETER(pid);
    if(info) return;
    KeAcquireSpinLock(&gbLock,&irql);
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) if(gbEntries[i] && gbEntries[i]->process==process) revoke(gbEntries[i]);
    KeReleaseSpinLock(&gbLock,irql);
}
static void NTAPI flowDelete(UINT16 layer,UINT32 callout,UINT64 context) {
    KIRQL irql; ULONG i; UNREFERENCED_PARAMETER(layer); UNREFERENCED_PARAMETER(callout);
    KeAcquireSpinLock(&gbLock,&irql);
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) if(gbEntries[i] && gbEntries[i]->record.cause==context) {
        // El grant de instancia vive aparte del primer socket; deny permanece hasta closure.
        gbEntries[i]->associated=FALSE; gbEntries[i]->deadFlow=TRUE; gbEntries[i]->receipt.current=0;
        break;
    }
    KeReleaseSpinLock(&gbLock,irql);
}
static void NTAPI packetClassify(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data,const void *context,const FWPS_FILTER3 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out) {
    GB_TUPLE t; GB_ENTRY *e; BOOLEAN ambiguous; KIRQL irql; UINT64 now=KeQueryInterruptTime();
    UNREFERENCED_PARAMETER(data); UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(filter);
    if(!tuple(v,m,&t)) { block(out); return; }
    KeAcquireSpinLock(&gbLock,&irql); e=endpoint(m,&t,FALSE,FALSE,&ambiguous);
    if(flow && (!e || e->record.cause!=flow || !e->associated ||
       !(m->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) || m->flowHandle!=e->receipt.flow)) ambiguous=TRUE;
    if(ambiguous || (e && (!live(e,now) || e->receipt.decision.action!=2))) block(out);
    else if(e) permit(out);
    else if(out->rights & FWPS_RIGHT_ACTION_WRITE) out->actionType=FWP_ACTION_CONTINUE;
    KeReleaseSpinLock(&gbLock,irql);
}
static void NTAPI closureClassify(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data,const void *context,const FWPS_FILTER3 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out) {
    ULONG i; KIRQL irql; GB_TUPLE t; FWP_BYTE_BLOB *app;
    UNREFERENCED_PARAMETER(data); UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(filter); UNREFERENCED_PARAMETER(flow);
    if(out->rights & FWPS_RIGHT_ACTION_WRITE) out->actionType=FWP_ACTION_CONTINUE;
    if(!tuple(v,m,&t) || !(m->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID) || m->compartmentId!=t.compartment ||
       !(m->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) ||
       !(m->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) || !m->transportEndpointHandle ||
       v->incomingValue[0].value.type!=FWP_BYTE_BLOB_TYPE) return;
    app=v->incomingValue[0].value.byteBlob;
    if(!app || !app->data || app->size>GB_CLASSIFIER_APP_BYTES) return;
    KeAcquireSpinLock(&gbLock,&irql);
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) if(gbEntries[i] && gbEntries[i]->record.endpoint==m->transportEndpointHandle &&
        sameTuple(gbEntries[i],&t) && gbEntries[i]->record.pid==m->processId &&
        gbEntries[i]->record.appBytes==app->size && RtlCompareMemory(gbEntries[i]->record.app,app->data,app->size)==app->size) {
        gbEntries[i]->closed=TRUE; gbEntries[i]->deadFlow=TRUE; gbEntries[i]->receipt.current=0;
    }
    KeReleaseSpinLock(&gbLock,irql);
}
static void NTAPI establishedClassify(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data,const void *context,const FWPS_FILTER3 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out) {
    GB_TUPLE t; GB_ENTRY *e; BOOLEAN ambiguous; KIRQL irql; UINT64 cause=0,id=0; UINT32 callout; UINT16 layer; NTSTATUS status;
    PACCESS_TOKEN token=NULL; FWP_BYTE_BLOB *app=NULL;
    UNREFERENCED_PARAMETER(data); UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(filter); UNREFERENCED_PARAMETER(flow);
    if(out->rights & FWPS_RIGHT_ACTION_WRITE) out->actionType=FWP_ACTION_CONTINUE;
    if(!tuple(v,m,&t)) return;
    if(v->incomingValue[0].value.type==FWP_BYTE_BLOB_TYPE) app=v->incomingValue[0].value.byteBlob;
    if(KeGetCurrentIrql()==PASSIVE_LEVEL && (m->currentMetadataValues & FWPS_METADATA_FIELD_TOKEN) && m->token)
        ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)m->token,TOKEN_QUERY,*SeTokenObjectType,KernelMode,(PVOID *)&token,NULL);
    KeAcquireSpinLock(&gbLock,&irql); e=endpoint(m,&t,TRUE,FALSE,&ambiguous);
    if(e || ambiguous) {
        if(!e || ambiguous || !live(e,KeQueryInterruptTime()) || e->receipt.decision.action!=2 ||
           !(m->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) || !m->flowHandle ||
           !(m->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) || m->processId!=e->record.pid ||
           token!=e->token || !app || !app->data || app->size!=e->record.appBytes ||
           RtlCompareMemory(app->data,e->record.app,app->size)!=app->size) {
            if(e) revoke(e);
            if(m->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) id=m->flowHandle;
        } else if(!e->associated) {
            cause=e->record.cause; id=m->flowHandle; e->receipt.flow=id; e->associated=TRUE;
        } else if(e->receipt.flow!=m->flowHandle) { revoke(e); id=m->flowHandle; }
    }
    KeReleaseSpinLock(&gbLock,irql);
    if(token) ObDereferenceObject(token);
    if(!cause) { if(id) FwpsFlowAbort0(id); return; }
    layer=t.family==4 ? FWPS_LAYER_STREAM_PACKET_V4 : FWPS_LAYER_STREAM_PACKET_V6;
    callout=gbCalloutIds[t.family==4 ? 2 : 3];
    status=FwpsFlowAssociateContext0(id,layer,callout,cause);
    if(!NT_SUCCESS(status)) {
        KeAcquireSpinLock(&gbLock,&irql); e=byCause(gbSession,cause);
        if(e) { e->associated=FALSE; revoke(e); }
        KeReleaseSpinLock(&gbLock,irql); FwpsFlowAbort0(id);
    }
}
static GB_ENTRY *capture(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    const FWPS_FILTER3 *filter,const GB_TUPLE *t,ULONG appField,ULONG flagsField) {
    GB_ENTRY *e=NULL; FWP_BYTE_BLOB *app; PTOKEN_USER user=NULL; PULONG container=NULL;
    PACCESS_TOKEN endpointToken=NULL; LARGE_INTEGER utc; NTSTATUS status;
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL ||
       !(m->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) || !m->processId ||
       !(m->currentMetadataValues & FWPS_METADATA_FIELD_TOKEN) || !m->token ||
       !(m->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) || !m->transportEndpointHandle ||
       (UINT64)(ULONG_PTR)PsGetProcessId(PsGetCurrentProcess())!=m->processId ||
       v->incomingValue[appField].value.type!=FWP_BYTE_BLOB_TYPE) return NULL;
    app=v->incomingValue[appField].value.byteBlob;
    if(!app || !app->data || app->size<4 || app->size>GB_CLASSIFIER_APP_BYTES || (app->size&1)) return NULL;
    e=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*e),GB_TAG); if(!e) return NULL;
    RtlZeroMemory(e,sizeof(*e)); e->process=PsGetCurrentProcess(); ObReferenceObject(e->process);
    e->token=PsReferencePrimaryToken(e->process);
    status=ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)m->token,TOKEN_QUERY,*SeTokenObjectType,KernelMode,(PVOID *)&endpointToken,NULL);
    if(!NT_SUCCESS(status) || endpointToken!=e->token) goto fail;
    ObDereferenceObject(endpointToken); endpointToken=NULL;
    status=SeQueryInformationToken(e->token,TokenIsAppContainer,(PVOID *)&container);
    if(!NT_SUCCESS(status) || !container || *container) goto fail;
    ExFreePool(container); container=NULL;
    status=SeQueryInformationToken(e->token,TokenUser,(PVOID *)&user);
    if(!NT_SUCCESS(status) || !user || !RtlValidSid(user->User.Sid) || RtlLengthSid(user->User.Sid)>GB_CLASSIFIER_SID_BYTES) goto fail;
    e->record.version=GB_CLASSIFIER_VERSION; e->record.bytes=sizeof(e->record);
    e->record.pid=m->processId; e->record.created=(UINT64)PsGetProcessCreateTimeQuadPart(e->process);
    e->record.endpoint=m->transportEndpointHandle; e->record.filterId=filter->filterId; e->record.layerId=v->layerId;
    e->record.flags=v->incomingValue[flagsField].value.uint32; e->record.compartment=t->compartment;
    e->record.family=t->family; e->record.protocol=6; e->record.localPort=t->localPort; e->record.remotePort=t->remotePort;
    RtlCopyMemory(e->record.localAddress,t->local,16); RtlCopyMemory(e->record.remoteAddress,t->remote,16);
    e->record.appBytes=app->size; RtlCopyMemory(e->record.app,app->data,app->size);
    e->record.userBytes=RtlLengthSid(user->User.Sid); RtlCopyMemory(e->record.user,user->User.Sid,e->record.userBytes);
    KeQuerySystemTimePrecise(&utc); e->record.timestamp=(UINT64)utc.QuadPart;
    ExFreePool(user); return e;
fail:
    if(endpointToken) ObDereferenceObject(endpointToken);
    if(container) ExFreePool(container);
    if(user) ExFreePool(user);
    freeEntry(e); return NULL;
}
static void NTAPI classify(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data,const void *context,const FWPS_FILTER3 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out) {
    ULONG protocolField,flagsField,appField,reasonField,i,empty=GB_CLASSIFIER_CAPACITY;
    GB_TUPLE t; GB_ENTRY *e,*grant=NULL; BOOLEAN ambiguous; KIRQL irql; UINT64 now=KeQueryInterruptTime();
    NTSTATUS status; HANDLE completion=NULL;
    UNREFERENCED_PARAMETER(data); UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(flow);
    if(!v || !m || !filter) { block(out); return; }
    if(v->layerId==FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        protocolField=FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL; flagsField=FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS;
        appField=FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID; reasonField=FWPS_FIELD_ALE_AUTH_CONNECT_V4_REAUTHORIZE_REASON;
    } else {
        protocolField=FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL; flagsField=FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS;
        appField=FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID; reasonField=FWPS_FIELD_ALE_AUTH_CONNECT_V6_REAUTHORIZE_REASON;
    }
    if(v->valueCount<=flagsField || v->incomingValue[protocolField].value.type!=FWP_UINT8 ||
       v->incomingValue[protocolField].value.uint8!=6) {
        if(out->rights & FWPS_RIGHT_ACTION_WRITE) out->actionType=FWP_ACTION_CONTINUE;
        return;
    }
    if(v->incomingValue[flagsField].value.type!=FWP_UINT32 || !tuple(v,m,&t) ||
       !(m->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID) || m->compartmentId!=t.compartment ||
       (v->incomingValue[flagsField].value.uint32 & FWP_CONDITION_FLAG_IS_RAW_ENDPOINT)) { block(out); return; }
    if(v->incomingValue[flagsField].value.uint32 & FWP_CONDITION_FLAG_IS_REAUTHORIZE) {
        KeAcquireSpinLock(&gbLock,&irql); e=endpoint(m,&t,FALSE,FALSE,&ambiguous);
        if(e && !ambiguous && e->completing && v->valueCount>reasonField &&
           v->incomingValue[reasonField].value.type==FWP_UINT32 &&
           v->incomingValue[reasonField].value.uint32==FWP_CONDITION_REAUTHORIZE_REASON_CLASSIFY_COMPLETION) {
            e->completing=FALSE; e->consumed=TRUE;
            if(!e->revoked && !e->closed && gbFile && e->record.session==gbSession && e->record.loss==gbLoss &&
               (e->receipt.decision.scope!=GB_SCOPE_DURATION || now<e->receipt.deadline) &&
               ((out->rights & FWPS_RIGHT_ACTION_WRITE) || out->actionType==FWP_ACTION_PERMIT ||
                (e->receipt.decision.action==1 && out->actionType==FWP_ACTION_BLOCK))) {
                e->receipt.applied=1; e->receipt.state=GB_SCOPE_APPLIED; e->receipt.observedAt=now; e->receipt.current=1;
                retireFutureRoots(e);
            }
        }
        if(e && !ambiguous && live(e,now) && e->receipt.decision.action==2) permit(out);
        else block(out);
        KeReleaseSpinLock(&gbLock,irql); return;
    }
    if(v->valueCount<=appField || !(m->currentMetadataValues & FWPS_METADATA_FIELD_COMPLETION_HANDLE) || !m->completionHandle) { block(out); return; }
    e=capture(v,m,filter,&t,appField,flagsField);
    if(!e) { KeAcquireSpinLock(&gbLock,&irql); if(gbFile) loss(); KeReleaseSpinLock(&gbLock,irql); block(out); return; }
    KeAcquireSpinLock(&gbLock,&irql);
    if(!gbFile || gbFault || gbLoss==GB_MAX64 || gbSequence==GB_MAX64) goto deny;
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) {
        GB_ENTRY *p=gbEntries[i];
        if(!p) { if(empty==GB_CLASSIFIER_CAPACITY) empty=i; continue; }
        if(!p->closed && p->record.endpoint==e->record.endpoint && sameTuple(p,&t)) goto deny;
    }
    grant=futureRoot(e,now,&ambiguous);
    if(ambiguous) { loss(); goto deny; }
    if(empty==GB_CLASSIFIER_CAPACITY) { loss(); goto deny; }
    e->record.session=gbSession; e->record.cause=++gbSequence; e->record.loss=gbLoss;
    e->pendingDeadline=now+GB_PENDING_TICKS;
    if(grant) {
        e->parent=grant->record.cause; e->receipt=grant->receipt;
        e->receipt.flow=0; e->receipt.decision.cause=e->record.cause; e->consumed=TRUE; e->delivered=TRUE;
        gbEntries[empty]=e;
        if(e->receipt.decision.action==2) permit(out); else block(out);
        KeReleaseSpinLock(&gbLock,irql); return;
    }
    // El contexto se publica bajo lock antes de que ordinary pueda entregar su decisión.
    status=FwpsPendOperation0(m->completionHandle,&completion);
    if(!NT_SUCCESS(status) || !completion) goto deny;
    e->completion=completion; e->receipt.state=GB_SCOPE_PENDING; gbEntries[empty]=e;
    block(out); out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    KeReleaseSpinLock(&gbLock,irql); return;
deny:
    KeReleaseSpinLock(&gbLock,irql); freeEntry(e); block(out);
}
static void NTAPI heldGuardClassify(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data,const void *context,const FWPS_FILTER3 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out) {
    ULONG protocol,flags,reason; GB_TUPLE t; GB_ENTRY *e; BOOLEAN ambiguous,completion; KIRQL irql;
    UINT64 now=KeQueryInterruptTime();
    UNREFERENCED_PARAMETER(data); UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(filter); UNREFERENCED_PARAMETER(flow);
    if(out->rights & FWPS_RIGHT_ACTION_WRITE) out->actionType=FWP_ACTION_CONTINUE;
    if(!v || !m) { block(out); return; }
    protocol=v->layerId==FWPS_LAYER_ALE_AUTH_CONNECT_V4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL : FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
    flags=v->layerId==FWPS_LAYER_ALE_AUTH_CONNECT_V4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS : FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS;
    reason=v->layerId==FWPS_LAYER_ALE_AUTH_CONNECT_V4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_REAUTHORIZE_REASON : FWPS_FIELD_ALE_AUTH_CONNECT_V6_REAUTHORIZE_REASON;
    if(v->valueCount<=flags || v->incomingValue[protocol].value.type!=FWP_UINT8 || v->incomingValue[protocol].value.uint8!=6) return;
    if(!tuple(v,m,&t) || v->incomingValue[flags].value.type!=FWP_UINT32) { block(out); return; }
    completion=(v->incomingValue[flags].value.uint32 & FWP_CONDITION_FLAG_IS_REAUTHORIZE) && v->valueCount>reason &&
        v->incomingValue[reason].value.type==FWP_UINT32 && v->incomingValue[reason].value.uint32==FWP_CONDITION_REAUTHORIZE_REASON_CLASSIFY_COMPLETION;
    KeAcquireSpinLock(&gbLock,&irql); e=endpoint(m,&t,FALSE,TRUE,&ambiguous);
    if(ambiguous) block(out);
    else if(e) {
        if(e->cancel.guarded) {
            block(out);
            if(completion && e->completing && out->actionType==FWP_ACTION_BLOCK) {
                // Describe esta clasificación final negativa; no fabrica un ACK OS de Complete.
                e->completing=FALSE; e->consumed=TRUE;
                e->cancel.reauthDenied=1; e->cancel.deniedAt=now;
            }
        } else if((out->rights & FWPS_RIGHT_ACTION_WRITE) &&
            (live(e,now) || (completion && e->completing && !e->revoked && !e->closed && gbFile && !gbFault &&
                e->record.session==gbSession && e->record.loss==gbLoss && e->receipt.decision.scope>=GB_SCOPE_ONCE &&
                e->receipt.decision.scope<=GB_SCOPE_DURATION &&
                (e->receipt.decision.scope!=GB_SCOPE_DURATION || now<e->receipt.deadline)))) {
            // Nunca Permit ni consume aquí: Block200 conserva prioridad; scope50 decide.
            out->actionType=FWP_ACTION_CONTINUE;
        } else block(out);
    }
    KeReleaseSpinLock(&gbLock,irql);
}
static void maintenance(void *ignored) {
    HANDLE completions[GB_CLASSIFIER_CAPACITY]; UINT64 aborts[GB_CLASSIFIER_CAPACITY];
    GB_ENTRY *discard[GB_CLASSIFIER_CAPACITY]; ULONG nc=0,na=0,nd=0,i; KIRQL irql; UINT64 now=KeQueryInterruptTime();
    UNREFERENCED_PARAMETER(ignored); controlEnter();
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) {
        GB_ENTRY *e;
        KeAcquireSpinLock(&gbLock,&irql); e=gbEntries[i]; KeReleaseSpinLock(&gbLock,irql);
        if(!e) continue;
        if(!currentEntry(e)) { KeAcquireSpinLock(&gbLock,&irql); revoke(e); KeReleaseSpinLock(&gbLock,irql); }
    }
    KeAcquireSpinLock(&gbLock,&irql);
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) {
        GB_ENTRY *e=gbEntries[i]; if(!e) continue;
        if((e->completion && now>=e->pendingDeadline) ||
           (e->receipt.decision.scope==GB_SCOPE_DURATION && now>=e->receipt.deadline)) revoke(e);
        if(e->revoked && e->completion) { completions[nc++]=e->completion; e->completion=NULL; e->completing=TRUE; }
        if(e->revoked && e->associated && e->receipt.flow) aborts[na++]=e->receipt.flow;
        if(e->closed && !e->completion && !e->completing && !e->associated && !e->cancelPin &&
           (e->revoked || !e->receipt.applied || e->receipt.decision.scope==GB_SCOPE_ONCE || e->parent)) {
            gbEntries[i]=NULL; discard[nd++]=e;
        }
    }
    KeReleaseSpinLock(&gbLock,irql);
    // Complete/Abort reentran classify/flowDelete: no retener el spinlock.
    for(i=0;i<nc;++i) FwpsCompleteOperation0(completions[i],NULL);
    for(i=0;i<na;++i) FwpsFlowAbort0(aborts[i]);
    for(i=0;i<nd;++i) freeEntry(discard[i]);
    controlLeave(); InterlockedExchange(&gbQueued,0);
}
static void NTAPI timerDpc(KDPC *dpc,void *context,void *arg1,void *arg2) {
    UNREFERENCED_PARAMETER(dpc); UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(arg1); UNREFERENCED_PARAMETER(arg2);
    if(InterlockedCompareExchange(&gbQueued,1,0)==0) ExQueueWorkItem(&gbWork,DelayedWorkQueue);
}
static NTSTATUS NTAPI notify(FWPS_CALLOUT_NOTIFY_TYPE type,const GUID *key,FWPS_FILTER3 *filter) {
    UNREFERENCED_PARAMETER(type); UNREFERENCED_PARAMETER(key); UNREFERENCED_PARAMETER(filter); return STATUS_SUCCESS;
}
static NTSTATUS finish(PIRP irp,NTSTATUS status,ULONG_PTR bytes) {
    irp->IoStatus.Status=status; irp->IoStatus.Information=bytes; IoCompleteRequest(irp,IO_NO_INCREMENT); return status;
}
static BOOLEAN decisionValid(const GB_SCOPE_DECISION *d) {
    UCHAR zero[16]={0};
    return d->version==GB_CLASSIFIER_VERSION && d->bytes==sizeof(*d) && d->session && d->cause && d->revision &&
        !d->reserved && RtlCompareMemory(d->command,zero,16)!=16 && d->scope>=GB_SCOPE_ONCE && d->scope<=GB_SCOPE_DURATION &&
        (d->action==1 || d->action==2) && (d->scope==GB_SCOPE_DURATION ? d->durationMs && d->durationMs<=GB_SCOPE_MAX_MS : !d->durationMs);
}
static BOOLEAN cancelValid(const GB_SCOPE_DECISION *d) {
    UCHAR zero[16]={0};
    return d->version==GB_CLASSIFIER_VERSION && d->bytes==sizeof(*d) && d->session && d->cause && d->revision &&
        !d->reserved && RtlCompareMemory(d->command,zero,16)!=16 && d->scope==2 &&
        (d->action==1 || d->action==2) && !d->durationMs;
}
static NTSTATUS NTAPI dispatch(PDEVICE_OBJECT device,PIRP irp) {
    PIO_STACK_LOCATION s=IoGetCurrentIrpStackLocation(irp); NTSTATUS status=STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR bytes=0; UINT32 code,i; KIRQL irql; HANDLE completion=NULL; PEPROCESS owner=NULL;
    UNREFERENCED_PARAMETER(device);
    if(s->MajorFunction==IRP_MJ_CLOSE) return finish(irp,STATUS_SUCCESS,0);
    if(s->MajorFunction==IRP_MJ_CLEANUP && KeGetCurrentIrql()==PASSIVE_LEVEL) {
        controlEnter(); KeAcquireSpinLock(&gbLock,&irql);
        if(s->FileObject==gbFile) {
            for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) if(gbEntries[i]) revoke(gbEntries[i]);
            gbFile=NULL; owner=gbOwner; gbOwner=NULL;
        }
        KeReleaseSpinLock(&gbLock,irql); controlLeave(); if(owner) ObDereferenceObject(owner);
        return finish(irp,STATUS_SUCCESS,0);
    }
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL || irp->RequestorMode!=UserMode ||
       PsGetCurrentProcess()!=IoGetRequestorProcess(irp)) return finish(irp,STATUS_ACCESS_DENIED,0);
    controlEnter();
    if(s->MajorFunction==IRP_MJ_CREATE) {
        if(!gbFile && gbSession!=GB_MAX64 && serviceOwner()) {
            owner=PsGetCurrentProcess(); ObReferenceObject(owner);
            KeAcquireSpinLock(&gbLock,&irql); gbFile=s->FileObject; gbOwner=owner; ++gbSession;
            for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) if(gbEntries[i]) revoke(gbEntries[i]);
            gbLoss=0; KeReleaseSpinLock(&gbLock,irql); status=STATUS_SUCCESS;
        } else status=STATUS_SHARING_VIOLATION;
    } else if(s->MajorFunction==IRP_MJ_DEVICE_CONTROL && s->FileObject==gbFile && PsGetCurrentProcess()==gbOwner && serviceOwner()) {
        code=s->Parameters.DeviceIoControl.IoControlCode;
        if(code==GB_CLASSIFIER_START && !s->Parameters.DeviceIoControl.InputBufferLength && !s->Parameters.DeviceIoControl.OutputBufferLength)
            status=startClassifier();
        else if(gbFault || !gbStarted) status=STATUS_DEVICE_NOT_READY;
        else if(code==GB_CLASSIFIER_RESET && !s->Parameters.DeviceIoControl.InputBufferLength &&
            s->Parameters.DeviceIoControl.OutputBufferLength==sizeof(GB_CLASSIFIER_STATE)) {
            GB_CLASSIFIER_STATE *state=irp->AssociatedIrp.SystemBuffer;
            KeAcquireSpinLock(&gbLock,&irql);
            for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) if(gbEntries[i]) revoke(gbEntries[i]);
            state->session=gbSession; state->loss=gbLoss; KeReleaseSpinLock(&gbLock,irql);
            bytes=sizeof(*state); status=STATUS_SUCCESS;
        } else if(code==GB_CLASSIFIER_NEXT && !s->Parameters.DeviceIoControl.InputBufferLength &&
            s->Parameters.DeviceIoControl.OutputBufferLength==sizeof(GB_CLASSIFIER_RECORD)) {
            status=STATUS_NO_MORE_ENTRIES;
            for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) {
                GB_ENTRY *e; HANDLE handle=NULL; BOOLEAN eligible;
                KeAcquireSpinLock(&gbLock,&irql); e=gbEntries[i]; KeReleaseSpinLock(&gbLock,irql);
                if(!e) continue;
                KeAcquireSpinLock(&gbLock,&irql); eligible=!e->delivered && !e->revoked && !e->closed && e->completion &&
                    e->record.session==gbSession && e->record.loss==gbLoss; KeReleaseSpinLock(&gbLock,irql);
                if(!eligible) continue;
                if(!currentEntry(e)) { KeAcquireSpinLock(&gbLock,&irql); revoke(e); KeReleaseSpinLock(&gbLock,irql); continue; }
                status=ObOpenObjectByPointer(e->process,0,NULL,GB_QUERY_PROCESS|SYNCHRONIZE,*PsProcessType,KernelMode,&handle);
                if(!NT_SUCCESS(status)) break;
                KeAcquireSpinLock(&gbLock,&irql);
                if(e->revoked || e->closed || !e->completion) { KeReleaseSpinLock(&gbLock,irql); ZwClose(handle); status=STATUS_NO_MORE_ENTRIES; continue; }
                e->record.processHandle=(UINT64)(ULONG_PTR)handle; e->delivered=TRUE;
                RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,&e->record,sizeof(e->record));
                KeReleaseSpinLock(&gbLock,irql); bytes=sizeof(e->record); break;
            }
            if(status==STATUS_NO_MORE_ENTRIES && gbLoss) status=STATUS_DATA_ERROR;
        } else if((code==GB_CLASSIFIER_CURRENT || code==GB_CLASSIFIER_RELEASE) &&
            s->Parameters.DeviceIoControl.InputBufferLength==sizeof(GB_CLASSIFIER_QUERY) && !s->Parameters.DeviceIoControl.OutputBufferLength) {
            GB_CLASSIFIER_QUERY *q=irp->AssociatedIrp.SystemBuffer; GB_ENTRY *e;
            KeAcquireSpinLock(&gbLock,&irql); e=byCause(q->session,q->cause); KeReleaseSpinLock(&gbLock,irql);
            status=STATUS_NOT_FOUND;
            if(e && e->delivered) {
                BOOLEAN identity=currentEntry(e);
                KeAcquireSpinLock(&gbLock,&irql);
                if(code==GB_CLASSIFIER_RELEASE) {
                    e->cancelPin=FALSE;
                    if(!e->receipt.decision.revision) revoke(e);
                    status=STATUS_SUCCESS;
                } else status=identity && !e->revoked && !e->closed && e->completion &&
                    e->record.session==gbSession && e->record.loss==gbLoss ? STATUS_SUCCESS : STATUS_INVALID_CID;
                KeReleaseSpinLock(&gbLock,irql);
            }
        } else if((code==GB_CLASSIFIER_CANCEL || code==GB_CLASSIFIER_CANCEL_READBACK) &&
            s->Parameters.DeviceIoControl.InputBufferLength==sizeof(GB_SCOPE_DECISION) &&
            s->Parameters.DeviceIoControl.OutputBufferLength==sizeof(GB_CANCEL_RECEIPT)) {
            GB_SCOPE_DECISION d; GB_ENTRY *e;
            RtlCopyMemory(&d,irp->AssociatedIrp.SystemBuffer,sizeof(d)); status=STATUS_INVALID_PARAMETER;
            if(cancelValid(&d)) {
                KeAcquireSpinLock(&gbLock,&irql); e=byCause(d.session,d.cause); KeReleaseSpinLock(&gbLock,irql);
                status=STATUS_NOT_FOUND;
                if(e) {
                    BOOLEAN identity=currentEntry(e); UINT64 now=KeQueryInterruptTime();
                    KeAcquireSpinLock(&gbLock,&irql);
                    if(code==GB_CLASSIFIER_CANCEL && !e->cancel.decision.revision) {
                        BOOLEAN duplicate=FALSE;
                        for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) if(gbEntries[i] && gbEntries[i]!=e &&
                            ((gbEntries[i]->receipt.decision.revision && RtlCompareMemory(gbEntries[i]->receipt.decision.command,d.command,16)==16) ||
                             (gbEntries[i]->cancel.decision.revision && RtlCompareMemory(gbEntries[i]->cancel.decision.command,d.command,16)==16))) duplicate=TRUE;
                        if(duplicate) status=STATUS_OBJECT_NAME_COLLISION;
                        else if(!identity || !e->delivered || e->revoked || e->closed || !e->completion || e->receipt.decision.revision ||
                            e->record.session!=gbSession || e->record.loss!=gbLoss || now>=e->pendingDeadline) status=STATUS_INVALID_CID;
                        else {
                            revoke(e); e->cancel.decision=d; e->cancel.guarded=1; e->cancelPin=TRUE;
                            e->completing=TRUE; completion=e->completion; e->completion=NULL; status=STATUS_SUCCESS;
                        }
                    } else status=e->record.session==gbSession && e->cancel.guarded &&
                        RtlCompareMemory(&d,&e->cancel.decision,sizeof(d))==sizeof(d) ? STATUS_SUCCESS : STATUS_OBJECT_NAME_COLLISION;
                    if(NT_SUCCESS(status)) {
                        e->cancel.closed=e->closed ? 1u : 0u;
                        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,&e->cancel,sizeof(e->cancel)); bytes=sizeof(e->cancel);
                    }
                    KeReleaseSpinLock(&gbLock,irql);
                }
            }
        } else if((code==GB_CLASSIFIER_DECIDE || code==GB_CLASSIFIER_READBACK) &&
            s->Parameters.DeviceIoControl.InputBufferLength==sizeof(GB_SCOPE_DECISION) &&
            s->Parameters.DeviceIoControl.OutputBufferLength==sizeof(GB_SCOPE_RECEIPT)) {
            GB_SCOPE_DECISION d; GB_ENTRY *e;
            RtlCopyMemory(&d,irp->AssociatedIrp.SystemBuffer,sizeof(d)); status=STATUS_INVALID_PARAMETER;
            if(decisionValid(&d)) {
                KeAcquireSpinLock(&gbLock,&irql); e=byCause(d.session,d.cause); KeReleaseSpinLock(&gbLock,irql);
                status=STATUS_NOT_FOUND;
                if(e) {
                    BOOLEAN identity=currentEntry(e); UINT64 now=KeQueryInterruptTime();
                    KeAcquireSpinLock(&gbLock,&irql);
                    if(code==GB_CLASSIFIER_DECIDE && !e->receipt.decision.revision) {
                        BOOLEAN duplicate=FALSE;
                        for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) if(gbEntries[i] && gbEntries[i]!=e &&
                            ((gbEntries[i]->receipt.decision.revision &&
                              RtlCompareMemory(gbEntries[i]->receipt.decision.command,d.command,16)==16) ||
                             (gbEntries[i]->cancel.decision.revision &&
                              RtlCompareMemory(gbEntries[i]->cancel.decision.command,d.command,16)==16))) duplicate=TRUE;
                        if(duplicate) status=STATUS_OBJECT_NAME_COLLISION;
                        else if(!identity || !e->delivered || e->revoked || e->closed || !e->completion ||
                           e->record.session!=gbSession || e->record.loss!=gbLoss || now>=e->pendingDeadline) status=STATUS_INVALID_CID;
                        else {
                            e->receipt.decision=d; e->receipt.deadline=d.scope==GB_SCOPE_DURATION ? now+(UINT64)d.durationMs*10000 : 0;
                            e->receipt.state=GB_SCOPE_COMPLETING; e->completing=TRUE;
                            completion=e->completion; e->completion=NULL; status=STATUS_SUCCESS;
                        }
                    } else status=RtlCompareMemory(&d,&e->receipt.decision,sizeof(d))==sizeof(d) ? STATUS_SUCCESS : STATUS_OBJECT_NAME_COLLISION;
                    if(!identity) revoke(e);
                    if(NT_SUCCESS(status)) {
                        e->receipt.current=live(e,now) ? 1u : 0u;
                        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,&e->receipt,sizeof(e->receipt)); bytes=sizeof(e->receipt);
                    }
                    KeReleaseSpinLock(&gbLock,irql);
                }
            }
        }
    }
    controlLeave();
    if(completion) FwpsCompleteOperation0(completion,NULL);
    return finish(irp,status,bytes);
}
static NTSTATUS startClassifier(void) {
    FWPM_SESSION0 session={0}; FWPM_PROVIDER0 provider={0}; FWPM_SUBLAYER0 sublayer={0},*policy=NULL;
    const GUID *layers[GB_CALLOUT_COUNT]={&FWPM_LAYER_ALE_AUTH_CONNECT_V4,&FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &FWPM_LAYER_STREAM_PACKET_V4,&FWPM_LAYER_STREAM_PACKET_V6,&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,&FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4,&FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,&FWPM_LAYER_ALE_AUTH_CONNECT_V6};
    NTSTATUS status; UINT32 i; LARGE_INTEGER due;
    if(gbFault) return STATUS_DEVICE_NOT_READY;
    if(gbStarted) return STATUS_SUCCESS;
    session.flags=FWPM_SESSION_FLAG_DYNAMIC;
    status=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,&session,&gbEngine); if(!NT_SUCCESS(status)) goto fail;
    status=FwpmSubLayerGetByKey0(gbEngine,&GbPolicySublayer,&policy);
    if(!NT_SUCCESS(status) || !policy || !policy->providerKey ||
       RtlCompareMemory(policy->providerKey,&GbPolicyProvider,sizeof(GUID))!=sizeof(GUID) ||
       policy->weight!=0x7d00 || policy->flags!=FWPM_SUBLAYER_FLAG_PERSISTENT) {
        if(policy) FwpmFreeMemory0((void **)&policy);
        status=STATUS_DEVICE_NOT_READY; goto fail;
    }
    FwpmFreeMemory0((void **)&policy);
    status=PsSetCreateProcessNotifyRoutineEx(processExit,FALSE); if(!NT_SUCCESS(status)) goto fail;
    status=FwpmTransactionBegin0(gbEngine,0); if(!NT_SUCCESS(status)) goto fail;
    provider.providerKey=GbClassifierProvider; provider.displayData.name=L"LGA GateBouncer scoped classifier";
    status=FwpmProviderAdd0(gbEngine,&provider,NULL); if(!NT_SUCCESS(status)) goto abort;
    sublayer.subLayerKey=GbClassifierSublayer; sublayer.providerKey=(GUID *)&GbClassifierProvider;
    sublayer.displayData.name=L"LGA GateBouncer scoped packets"; sublayer.weight=65535;
    status=FwpmSubLayerAdd0(gbEngine,&sublayer,NULL); if(!NT_SUCCESS(status)) goto abort;
    for(i=0;i<GB_CALLOUT_COUNT;++i) {
        FWPS_CALLOUT3 runtime={0}; FWPM_CALLOUT0 callout={0}; FWPM_FILTER0 filter={0}; UINT64 weight=50;
        const GUID *key=i<2 ? &GbClassifierCallouts[i] : i<8 ? &GbScopeCallouts[i-2] : &GbHeldGuardCallouts[i-8];
        if(i>=8) weight=1000;
        runtime.calloutKey=*key; runtime.notifyFn=notify;
        runtime.classifyFn=i>=8 ? heldGuardClassify : i<2 ? classify : i<4 ? packetClassify : i<6 ? establishedClassify : closureClassify;
        if(i==2 || i==3) runtime.flowDeleteFn=flowDelete;
        status=FwpsCalloutRegister3(gbDevice,&runtime,&gbCalloutIds[i]); if(!NT_SUCCESS(status)) goto abort;
        callout.calloutKey=*key; callout.providerKey=(GUID *)&GbClassifierProvider;
        callout.displayData.name=L"LGA GateBouncer scoped TCP"; callout.applicableLayer=*layers[i];
        status=FwpmCalloutAdd0(gbEngine,&callout,NULL,NULL); if(!NT_SUCCESS(status)) goto abort;
        filter.filterKey=i<2 ? GbClassifierFilters[i] : *key; filter.providerKey=(GUID *)&GbClassifierProvider;
        filter.displayData.name=L"LGA GateBouncer scoped TCP"; filter.layerKey=*layers[i];
        filter.subLayerKey=(i<2 || i>=8) ? GbPolicySublayer : GbClassifierSublayer;
        filter.weight.type=FWP_UINT64; filter.weight.uint64=&weight;
        filter.action.type=(i<4 || i>=8) ? FWP_ACTION_CALLOUT_UNKNOWN : FWP_ACTION_CALLOUT_INSPECTION;
        filter.action.calloutKey=*key;
        status=FwpmFilterAdd0(gbEngine,&filter,NULL,NULL); if(!NT_SUCCESS(status)) goto abort;
    }
    status=FwpmTransactionCommit0(gbEngine); if(!NT_SUCCESS(status)) goto fail;
    gbStarted=TRUE; due.QuadPart=-1000000;
    KeSetTimerEx(&gbTimer,due,100,&gbDpc); return STATUS_SUCCESS;
abort:
    FwpmTransactionAbort0(gbEngine);
fail:
    gbFault=TRUE; return status;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING registry) {
    UNICODE_STRING deviceName=RTL_CONSTANT_STRING(L"\\Device\\LgaGateBouncerClassifier");
    UNICODE_STRING security=RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)"); NTSTATUS status;
    UNREFERENCED_PARAMETER(registry);
    ExInitializePushLock(&gbControl); KeInitializeSpinLock(&gbLock);
    KeInitializeTimer(&gbTimer); KeInitializeDpc(&gbDpc,timerDpc,NULL); ExInitializeWorkItem(&gbWork,maintenance,NULL);
    driver->MajorFunction[IRP_MJ_CREATE]=dispatch; driver->MajorFunction[IRP_MJ_CLEANUP]=dispatch;
    driver->MajorFunction[IRP_MJ_CLOSE]=dispatch; driver->MajorFunction[IRP_MJ_DEVICE_CONTROL]=dispatch;
    // La imagen permanece ante callbacks/fallo parcial hasta reboot del invitado.
    driver->DriverUnload=NULL;
    status=IoCreateDeviceSecure(driver,0,&deviceName,FILE_DEVICE_NETWORK,FILE_DEVICE_SECURE_OPEN,FALSE,
        &security,&GbClassifierProvider,&gbDevice); if(!NT_SUCCESS(status)) return status;
    status=IoCreateSymbolicLink(&gbLink,&deviceName);
    if(!NT_SUCCESS(status)) { IoDeleteDevice(gbDevice); gbDevice=NULL; return status; }
    gbDevice->Flags &= ~DO_DEVICE_INITIALIZING; return STATUS_SUCCESS;
}
