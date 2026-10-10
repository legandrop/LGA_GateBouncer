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
#define GB_CALLOUT_COUNT 18u
#define GB_PACKET_BYTES 65535u
C_ASSERT(sizeof(GB_ACTIVITY_SNAPSHOT)==168);
C_ASSERT(sizeof(GB_SCOPE_DECISION)==64);
C_ASSERT(sizeof(GB_SCOPE_RECEIPT)==104);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,decision)==8);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,loss)==72);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,authorizedUtc)==80);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,flow)==88);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,outboundBytes)==96);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,outboundPackets)==104);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,outboundUtc)==112);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,outboundRevision)==120);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,inboundBytes)==128);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,inboundPackets)==136);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,inboundUtc)==144);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,inboundRevision)==152);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,flags)==160);
C_ASSERT(FIELD_OFFSET(GB_ACTIVITY_SNAPSHOT,reserved)==164);
typedef struct GB_ENTRY {
    GB_CLASSIFIER_RECORD record;
    PEPROCESS process;
    PACCESS_TOKEN token;
    HANDLE completion;
    GB_SCOPE_RECEIPT receipt;
    GB_ACTIVITY_SNAPSHOT activity;
    GB_CANCEL_RECEIPT cancel;
    UINT64 pendingDeadline, parent;
    BOOLEAN delivered, revoked, closed, associated, completing, consumed, deadFlow;
    BOOLEAN cancelPin, futureRetired;
    BOOLEAN listener, injectQueued, injectActive, injectSeen;
    ULONG injectPins;
    ULONG associationPins;
    KDPC injectDpc;
    NET_BUFFER_LIST *packet;
    MDL *packetMdl;
    UCHAR *packetBytes;
    UINT32 interfaceIndex, subInterfaceIndex;
} GB_ENTRY;
typedef struct GB_TUPLE {
    UINT32 compartment;
    UINT16 localPort, remotePort;
    UCHAR family, protocol, local[16], remote[16];
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
static HANDLE gbInjection[2];
static NDIS_HANDLE gbPacketPool;
static UNICODE_STRING gbLink=RTL_CONSTANT_STRING(L"\\DosDevices\\LgaGateBouncerClassifier");
static NTSTATUS startClassifier(void);
static void queueInbound(GB_ENTRY *e,HANDLE completion);
static BOOLEAN inboundLayer(UINT16 layer) {
    return layer==FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 || layer==FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
}
static BOOLEAN sameAuthorization(const GB_ENTRY *a,const GB_ENTRY *b) {
    return a->record.protocol==b->record.protocol && inboundLayer(a->record.layerId)==inboundLayer(b->record.layerId);
}
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
static void appliedUtc(GB_ENTRY *e) {
    LARGE_INTEGER utc;
    if(e->activity.flags & GB_ACTIVITY_AUTH_UTC)return;
    KeQuerySystemTimePrecise(&utc);
    if(utc.QuadPart>0) { e->activity.authorizedUtc=(UINT64)utc.QuadPart;e->activity.flags|=GB_ACTIVITY_AUTH_UTC; }
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
           !sameAuthorization(p,e) || !sameInstance(p,e)) continue;
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
        if(p->record.session==e->record.session && p->record.loss==e->record.loss &&
            sameAuthorization(p,e) && sameInstance(p,e)) p->futureRetired=TRUE;
    }
    e->futureRetired=FALSE;
}
static BOOLEAN retireable(GB_ENTRY *e) {
    ULONG i;
    // UDP: closure/idle no prueban ausencia de callback tardío sin contexto.
    if(e->record.protocol==IPPROTO_UDP || e->associationPins)return FALSE;
    if(!e->closed || e->completion || e->completing || e->associated || e->cancelPin ||
        e->packet || e->injectQueued || e->injectActive || e->injectPins)return FALSE;
    for(i=0;!e->parent && i<GB_CLASSIFIER_CAPACITY;++i) {
        GB_ENTRY *p=gbEntries[i];
        if(p && p!=e && p->record.session==e->record.session && p->parent==e->record.cause)return FALSE;
    }
    return e->revoked || !e->receipt.applied || e->receipt.decision.scope==GB_SCOPE_ONCE || e->parent || e->futureRetired;
}
static void revoke(GB_ENTRY *e) {
    e->revoked=TRUE; e->receipt.current=0;
    e->receipt.state=e->closed ? GB_SCOPE_CLOSED : GB_SCOPE_REVOKED;
}
static void drainDeniedCompletion(GB_ENTRY *e,BOOLEAN exactCompletion,FWP_ACTION_TYPE action) {
    if(exactCompletion && e->completing && action==FWP_ACTION_BLOCK) {
        // Clasificación negativa exacta, no ACK de Complete ni Applied temporal.
        revoke(e);e->completing=FALSE;e->consumed=TRUE;
    }
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
    ULONG la,ra,lp,rp,c,protocol; BOOLEAN packet,flow,closure,datagram; UINT32 compartment;
    if(!v || !m) return FALSE;
    packet=v->layerId==FWPS_LAYER_STREAM_PACKET_V4 || v->layerId==FWPS_LAYER_STREAM_PACKET_V6;
    flow=v->layerId==FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 || v->layerId==FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6;
    closure=v->layerId==FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4 || v->layerId==FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V6;
    datagram=v->layerId==FWPS_LAYER_DATAGRAM_DATA_V4 || v->layerId==FWPS_LAYER_DATAGRAM_DATA_V6;
    RtlZeroMemory(t,sizeof(*t));
    t->family=(v->layerId==FWPS_LAYER_STREAM_PACKET_V4 || v->layerId==FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 ||
        v->layerId==FWPS_LAYER_ALE_AUTH_CONNECT_V4 || v->layerId==FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 ||
        v->layerId==FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4 || v->layerId==FWPS_LAYER_DATAGRAM_DATA_V4) ? 4 : 6;
    protocol=t->family==4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL : FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
    if(packet) {
        la=0; ra=1; lp=2; rp=3;
        c=t->family==4 ? FWPS_FIELD_STREAM_PACKET_V4_COMPARTMENT_ID : FWPS_FIELD_STREAM_PACKET_V6_COMPARTMENT_ID;
    } else if(datagram) {
        la=t->family==4 ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS : FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_ADDRESS;
        ra=t->family==4 ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS : FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS;
        lp=t->family==4 ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT : FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT;
        rp=t->family==4 ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT : FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT;
        c=t->family==4 ? FWPS_FIELD_DATAGRAM_DATA_V4_COMPARTMENT_ID : FWPS_FIELD_DATAGRAM_DATA_V6_COMPARTMENT_ID;
        protocol=t->family==4 ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL : FWPS_FIELD_DATAGRAM_DATA_V6_IP_PROTOCOL;
    } else {
        la=2; ra=6; lp=4; rp=7;
        if(flow) {
            c=t->family==4 ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_COMPARTMENT_ID : FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_COMPARTMENT_ID;
            protocol=t->family==4 ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL : FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL;
        } else if(closure) {
            c=t->family==4 ? FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_COMPARTMENT_ID : FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_COMPARTMENT_ID;
            protocol=t->family==4 ? FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_PROTOCOL : FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_PROTOCOL;
        }
        else if(inboundLayer(v->layerId)) {
            la=2;lp=4;ra=6;rp=7;
            c=t->family==4 ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_COMPARTMENT_ID : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_COMPARTMENT_ID;
            protocol=t->family==4 ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
        } else c=t->family==4 ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_COMPARTMENT_ID : FWPS_FIELD_ALE_AUTH_CONNECT_V6_COMPARTMENT_ID;
    }
    if(v->valueCount<=c || v->valueCount<=rp || v->incomingValue[c].value.type!=FWP_UINT32 ||
       v->incomingValue[lp].value.type!=FWP_UINT16 || v->incomingValue[rp].value.type!=FWP_UINT16) return FALSE;
    if(packet)t->protocol=IPPROTO_TCP;
    else {
        if(v->valueCount<=protocol || v->incomingValue[protocol].value.type!=FWP_UINT8)return FALSE;
        t->protocol=v->incomingValue[protocol].value.uint8;
    }
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
    return e->record.family==t->family && e->record.protocol==t->protocol && e->record.compartment==t->compartment &&
        e->record.localPort==t->localPort && e->record.remotePort==t->remotePort &&
        RtlCompareMemory(e->record.localAddress,t->local,16)==16 && RtlCompareMemory(e->record.remoteAddress,t->remote,16)==16;
}
static ULONG slotFor(GB_ENTRY *e,const GB_TUPLE *t,BOOLEAN *duplicate) {
    ULONG i,empty=GB_CLASSIFIER_CAPACITY;*duplicate=FALSE;
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) {
        GB_ENTRY *p=gbEntries[i];
        if(!p){if(empty==GB_CLASSIFIER_CAPACITY)empty=i;continue;}
        if((!p->closed || p->record.protocol==IPPROTO_UDP) && p->record.endpoint==e->record.endpoint && sameTuple(p,t))*duplicate=TRUE;
    }
    return empty;
}
static GB_ENTRY *endpoint(const FWPS_INCOMING_METADATA_VALUES0 *m,const GB_TUPLE *t,BOOLEAN fieldCompartment,BOOLEAN closingCompletion,BOOLEAN *ambiguous) {
    GB_ENTRY *found=NULL; ULONG i; *ambiguous=FALSE;
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) {
        GB_ENTRY *e=gbEntries[i];
        if(!e || (e->closed && e->record.protocol!=IPPROTO_UDP && !(closingCompletion && e->completing)) || !sameTuple(e,t)) continue;
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
        gbEntries[i]->activity.flags|=GB_ACTIVITY_INCOMPLETE;
        break;
    }
    KeReleaseSpinLock(&gbLock,irql);
}
typedef struct GB_PACKET_OBSERVATION { UINT64 bytes, packets; BOOLEAN complete; } GB_PACKET_OBSERVATION;
// Punteros prestados del callback: recorrido finito, sin guardar ni cambiar listas.
static GB_PACKET_OBSERVATION packetObservation(void *data) {
    GB_PACKET_OBSERVATION result={0,0,FALSE};
    NET_BUFFER_LIST *list=(NET_BUFFER_LIST *)data,*lists[64];
    NET_BUFFER *buffers[64]; ULONG listCount=0,bufferCount=0,i;
    if(!list)return result;
    while(list) {
        NET_BUFFER *buffer;
        if(listCount==64)return result;
        for(i=0;i<listCount;++i)if(lists[i]==list)return result;
        lists[listCount++]=list;buffer=NET_BUFFER_LIST_FIRST_NB(list);
        if(!buffer)return result;
        while(buffer) {
            UINT64 size=(UINT64)NET_BUFFER_DATA_LENGTH(buffer);
            if(bufferCount==64 || size>GB_MAX64-result.bytes)return result;
            for(i=0;i<bufferCount;++i)if(buffers[i]==buffer)return result;
            buffers[bufferCount++]=buffer;result.bytes+=size;++result.packets;
            buffer=NET_BUFFER_NEXT_NB(buffer);
        }
        list=NET_BUFFER_LIST_NEXT_NBL(list);
    }
    result.complete=result.packets!=0;return result;
}
static void accumulateActivity(GB_ENTRY *e,UINT32 direction,GB_PACKET_OBSERVATION packet,BOOLEAN fieldsValid) {
    UINT64 *bytes,*packets,*utc,*revision;UINT32 flag;LARGE_INTEGER now;
    if(!fieldsValid || !packet.complete ||
       (direction!=(UINT32)FWP_DIRECTION_OUTBOUND && direction!=(UINT32)FWP_DIRECTION_INBOUND)) {
        e->activity.flags|=GB_ACTIVITY_INCOMPLETE;return;
    }
    if(e->activity.flags & GB_ACTIVITY_INCOMPLETE)return;
    if(direction==(UINT32)FWP_DIRECTION_OUTBOUND) {
        bytes=&e->activity.outboundBytes;packets=&e->activity.outboundPackets;
        utc=&e->activity.outboundUtc;revision=&e->activity.outboundRevision;flag=GB_ACTIVITY_OUTBOUND;
    } else {
        bytes=&e->activity.inboundBytes;packets=&e->activity.inboundPackets;
        utc=&e->activity.inboundUtc;revision=&e->activity.inboundRevision;flag=GB_ACTIVITY_INBOUND;
    }
    KeQuerySystemTimePrecise(&now);
    if(packet.bytes>GB_MAX64-*bytes || packet.packets>GB_MAX64-*packets || *revision==GB_MAX64 ||
       now.QuadPart<=0 || (UINT64)now.QuadPart<*utc) {e->activity.flags|=GB_ACTIVITY_INCOMPLETE;return;}
    *bytes+=packet.bytes;*packets+=packet.packets;*utc=(UINT64)now.QuadPart;++*revision;e->activity.flags|=flag;
}
static void NTAPI packetClassify(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data,const void *context,const FWPS_FILTER3 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out) {
    GB_TUPLE t; GB_ENTRY *e; BOOLEAN ambiguous; KIRQL irql; UINT64 now=KeQueryInterruptTime();
    GB_PACKET_OBSERVATION packet=packetObservation(data);ULONG direction,flags;BOOLEAN fieldsValid;
    UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(filter);
    if(!tuple(v,m,&t)) { block(out); return; }
    direction=t.family==4 ? FWPS_FIELD_STREAM_PACKET_V4_DIRECTION : FWPS_FIELD_STREAM_PACKET_V6_DIRECTION;
    flags=t.family==4 ? FWPS_FIELD_STREAM_PACKET_V4_FLAGS : FWPS_FIELD_STREAM_PACKET_V6_FLAGS;
    fieldsValid=v->valueCount>flags && v->valueCount>direction &&
        v->incomingValue[direction].value.type==FWP_UINT32 && v->incomingValue[flags].value.type==FWP_UINT32 &&
        !(v->incomingValue[flags].value.uint32 & (FWP_CONDITION_FLAG_IS_RAW_ENDPOINT | FWP_CONDITION_FLAG_IS_FRAGMENT |
          FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP | FWP_CONDITION_FLAG_IS_IPSEC_SECURED));
    KeAcquireSpinLock(&gbLock,&irql); e=endpoint(m,&t,FALSE,FALSE,&ambiguous);
    if(flow && (!e || e->record.cause!=flow || !e->associated ||
       !(m->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) || m->flowHandle!=e->receipt.flow)) ambiguous=TRUE;
    if(ambiguous || (e && (!live(e,now) || e->receipt.decision.action!=2))) block(out);
    else if(e) {
        permit(out);
        if(data && flow && e->record.cause==flow && e->associated && !e->associationPins &&
           (m->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) && m->flowHandle && m->flowHandle==e->receipt.flow &&
           (m->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) && m->transportEndpointHandle==e->record.endpoint &&
           (m->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID) && m->compartmentId==e->record.compartment &&
           out->actionType==FWP_ACTION_PERMIT)
            accumulateActivity(e,fieldsValid ? v->incomingValue[direction].value.uint32 : FWP_DIRECTION_MAX,packet,fieldsValid);
    }
    else if(out->rights & FWPS_RIGHT_ACTION_WRITE) out->actionType=FWP_ACTION_CONTINUE;
    KeReleaseSpinLock(&gbLock,irql);
}
static BOOLEAN datagramBound(GB_ENTRY *e,const GB_TUPLE *t,const FWPS_INCOMING_METADATA_VALUES0 *m,UINT64 context,UINT64 now) {
    return e && context && e->record.cause==context && e->record.protocol==IPPROTO_UDP &&
        e->associated && !e->associationPins && live(e,now) && sameTuple(e,t) &&
        (m->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) && m->flowHandle && m->flowHandle==e->receipt.flow &&
        (m->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) && m->transportEndpointHandle==e->record.endpoint &&
        (m->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID) && m->compartmentId==e->record.compartment;
}
static void NTAPI datagramClassify(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data,const void *context,const FWPS_FILTER3 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out) {
    GB_TUPLE t;GB_ENTRY *e;ULONG protocol,direction,flags;BOOLEAN ambiguous=FALSE;KIRQL irql;
    GB_PACKET_OBSERVATION packet;
    UNREFERENCED_PARAMETER(context);UNREFERENCED_PARAMETER(filter);
    if(out->rights & FWPS_RIGHT_ACTION_WRITE)out->actionType=FWP_ACTION_CONTINUE;
    if(!v || !m){block(out);return;}
    protocol=v->layerId==FWPS_LAYER_DATAGRAM_DATA_V4 ? FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL : FWPS_FIELD_DATAGRAM_DATA_V6_IP_PROTOCOL;
    direction=v->layerId==FWPS_LAYER_DATAGRAM_DATA_V4 ? FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION : FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION;
    flags=v->layerId==FWPS_LAYER_DATAGRAM_DATA_V4 ? FWPS_FIELD_DATAGRAM_DATA_V4_FLAGS : FWPS_FIELD_DATAGRAM_DATA_V6_FLAGS;
    if(v->valueCount<=protocol || v->incomingValue[protocol].value.type!=FWP_UINT8){block(out);return;}
    if(v->incomingValue[protocol].value.uint8!=IPPROTO_UDP)return;
    if(!tuple(v,m,&t)){block(out);return;}
    packet=packetObservation(data);
    if(v->valueCount<=flags || v->valueCount<=direction || v->incomingValue[direction].value.type!=FWP_UINT32 ||
        (v->incomingValue[direction].value.uint32!=(UINT32)FWP_DIRECTION_INBOUND &&
         v->incomingValue[direction].value.uint32!=(UINT32)FWP_DIRECTION_OUTBOUND) ||
        v->incomingValue[flags].value.type!=FWP_UINT32) {
        KeAcquireSpinLock(&gbLock,&irql);e=flow ? byCause(gbSession,flow) : NULL;
        if(datagramBound(e,&t,m,flow,KeQueryInterruptTime()) && e->receipt.decision.action==2)
            e->activity.flags|=GB_ACTIVITY_INCOMPLETE;
        KeReleaseSpinLock(&gbLock,irql);block(out);return;
    }
    KeAcquireSpinLock(&gbLock,&irql);
    e=flow ? byCause(gbSession,flow) : endpoint(m,&t,FALSE,TRUE,&ambiguous);
    if(flow) {
        if(!datagramBound(e,&t,m,flow,KeQueryInterruptTime()) || e->receipt.decision.action!=2 ||
            (v->incomingValue[flags].value.uint32 & (FWP_CONDITION_FLAG_IS_RAW_ENDPOINT | FWP_CONDITION_FLAG_IS_FRAGMENT |
                FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP | FWP_CONDITION_FLAG_IS_IPSEC_SECURED))) {
            if(datagramBound(e,&t,m,flow,KeQueryInterruptTime()) && e->receipt.decision.action==2)
                e->activity.flags|=GB_ACTIVITY_INCOMPLETE;
            block(out);
        }
        else {
            permit(out);
            if(data && out->actionType==FWP_ACTION_PERMIT)
                accumulateActivity(e,v->incomingValue[direction].value.uint32,packet,TRUE);
        }
    } else if(e || ambiguous)block(out);
    // Sin scope temporal: continuar hacia la autorización permanente vigente, no fabricar Permit.
    KeReleaseSpinLock(&gbLock,irql);
}
static void closeUdpEndpoint(UINT64 endpointId,UINT64 pid,UCHAR family,UINT32 compartment,const FWP_BYTE_BLOB *app) {
    ULONG i;
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i) {
        GB_ENTRY *e=gbEntries[i];
        if(e && e->record.protocol==IPPROTO_UDP && e->record.endpoint==endpointId &&
            e->record.family==family && e->record.compartment==compartment && e->record.pid==pid &&
            e->record.appBytes==app->size && RtlCompareMemory(e->record.app,app->data,app->size)==app->size) {
            e->closed=TRUE;e->deadFlow=TRUE;revoke(e);
        }
    }
}
static void NTAPI closureClassify(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data,const void *context,const FWPS_FILTER3 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out) {
    ULONG i; KIRQL irql; GB_TUPLE t; FWP_BYTE_BLOB *app;
    UNREFERENCED_PARAMETER(data); UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(filter); UNREFERENCED_PARAMETER(flow);
    if(out->rights & FWPS_RIGHT_ACTION_WRITE) out->actionType=FWP_ACTION_CONTINUE;
    if(v && m && v->valueCount && v->incomingValue[0].value.type==FWP_BYTE_BLOB_TYPE &&
        (m->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) &&
        (m->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        FWP_BYTE_BLOB *identity=v->incomingValue[0].value.byteBlob;
        KeAcquireSpinLock(&gbLock,&irql);
        for(i=0;i<GB_CLASSIFIER_CAPACITY;++i)if(gbEntries[i] && gbEntries[i]->listener && identity && identity->data &&
            gbEntries[i]->record.endpoint==m->transportEndpointHandle && gbEntries[i]->record.pid==m->processId &&
            identity->size==gbEntries[i]->record.appBytes &&
            RtlCompareMemory(identity->data,gbEntries[i]->record.app,identity->size)==identity->size) {
            gbEntries[i]->closed=TRUE;revoke(gbEntries[i]);
        }
        KeReleaseSpinLock(&gbLock,irql);
    }
    if(v && m) {
        UCHAR family=v->layerId==FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4 ? 4 : 6;
        ULONG p=family==4 ? FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_PROTOCOL : FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_PROTOCOL;
        ULONG c=family==4 ? FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_COMPARTMENT_ID : FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_COMPARTMENT_ID;
        // UDP closure no exige remoto: el OS indica un cierre por endpoint para todos los peers.
        if(v->valueCount>c && v->incomingValue[p].value.type==FWP_UINT8 && v->incomingValue[p].value.uint8==IPPROTO_UDP) {
            if(v->incomingValue[c].value.type!=FWP_UINT32 || v->incomingValue[0].value.type!=FWP_BYTE_BLOB_TYPE ||
                !(m->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID) ||
                m->compartmentId!=v->incomingValue[c].value.uint32 ||
                !(m->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) ||
                !(m->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) || !m->transportEndpointHandle)return;
            app=v->incomingValue[0].value.byteBlob;
            if(!app || !app->data || !app->size || app->size>GB_CLASSIFIER_APP_BYTES)return;
            KeAcquireSpinLock(&gbLock,&irql);
            closeUdpEndpoint(m->transportEndpointHandle,m->processId,family,m->compartmentId,app);
            KeReleaseSpinLock(&gbLock,irql);return;
        }
    }
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
static BOOLEAN publishUdpAssociation(GB_ENTRY *e,UINT64 id,NTSTATUS status,UINT64 now) {
    if(e && status==STATUS_SUCCESS && e->associationPins && !e->deadFlow && live(e,now) &&
        e->receipt.flow==id && e->record.session==gbSession && e->record.loss==gbLoss) {
        e->associated=TRUE;return TRUE;
    }
    if(e)revoke(e);
    return FALSE;
}
static void udpEstablished(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,const GB_TUPLE *t) {
    GB_ENTRY *e=NULL;BOOLEAN ambiguous,accepted=FALSE;KIRQL irql;PACCESS_TOKEN token=NULL;FWP_BYTE_BLOB *app=NULL;
    UINT64 cause=0,session=0,id=0;UINT16 layer;UINT32 callout;NTSTATUS status;
    ULONG direction=t->family==4 ? FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION : FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION;
    if(v->incomingValue[0].value.type==FWP_BYTE_BLOB_TYPE)app=v->incomingValue[0].value.byteBlob;
    if(KeGetCurrentIrql()==PASSIVE_LEVEL && (m->currentMetadataValues & FWPS_METADATA_FIELD_TOKEN) && m->token)
        ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)m->token,TOKEN_QUERY,*SeTokenObjectType,KernelMode,(PVOID *)&token,NULL);
    KeAcquireSpinLock(&gbLock,&irql);e=endpoint(m,t,TRUE,TRUE,&ambiguous);
    if(e || ambiguous) {
        if(!e || ambiguous || !live(e,KeQueryInterruptTime()) || e->receipt.decision.action!=2 || e->associationPins ||
            !(m->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) || !m->flowHandle ||
            !(m->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) || m->processId!=e->record.pid ||
            v->valueCount<=direction || v->incomingValue[direction].value.type!=FWP_UINT32 ||
            v->incomingValue[direction].value.uint32!=(UINT32)(inboundLayer(e->record.layerId) ? FWP_DIRECTION_INBOUND : FWP_DIRECTION_OUTBOUND) ||
            token!=e->token || !app || !app->data || app->size!=e->record.appBytes ||
            RtlCompareMemory(app->data,e->record.app,app->size)!=app->size) {
            if(e)revoke(e);
            if(m->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE)id=m->flowHandle;
        } else if(!e->associated) {
            id=m->flowHandle;cause=e->record.cause;session=e->record.session;
            e->receipt.flow=id;++e->associationPins;
        } else if(e->receipt.flow!=m->flowHandle){revoke(e);id=m->flowHandle;}
    }
    KeReleaseSpinLock(&gbLock,irql);if(token)ObDereferenceObject(token);
    if(!cause){if(id)FwpsFlowAbort0(id);return;}
    layer=(UINT16)(t->family==4 ? FWPS_LAYER_DATAGRAM_DATA_V4 : FWPS_LAYER_DATAGRAM_DATA_V6);
    callout=gbCalloutIds[t->family==4 ? 16 : 17];
    status=FwpsFlowAssociateContext0(id,layer,callout,cause);
    KeAcquireSpinLock(&gbLock,&irql);e=byCause(session,cause);
    accepted=publishUdpAssociation(e,id,status,KeQueryInterruptTime());
    KeReleaseSpinLock(&gbLock,irql);
    // Sólo retirar el contexto creado por esta operación; nunca reemplazar el ajeno.
    if(status==STATUS_SUCCESS && !accepted)FwpsFlowRemoveContext0(id,layer,callout);
    KeAcquireSpinLock(&gbLock,&irql);e=byCause(session,cause);if(e)--e->associationPins;
    KeReleaseSpinLock(&gbLock,irql);if(!accepted)FwpsFlowAbort0(id);
}
static void NTAPI establishedClassify(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data,const void *context,const FWPS_FILTER3 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out) {
    GB_TUPLE t; GB_ENTRY *e; BOOLEAN ambiguous; KIRQL irql; UINT64 cause=0,id=0; UINT32 callout; UINT16 layer; NTSTATUS status;
    PACCESS_TOKEN token=NULL; FWP_BYTE_BLOB *app=NULL;
    UNREFERENCED_PARAMETER(data); UNREFERENCED_PARAMETER(context); UNREFERENCED_PARAMETER(filter); UNREFERENCED_PARAMETER(flow);
    if(out->rights & FWPS_RIGHT_ACTION_WRITE) out->actionType=FWP_ACTION_CONTINUE;
    if(!tuple(v,m,&t)) return;
    if(t.protocol==IPPROTO_UDP){udpEstablished(v,m,&t);return;}
    if(t.protocol!=IPPROTO_TCP)return;
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
    e->record.family=t->family; e->record.protocol=t->protocol; e->record.localPort=t->localPort; e->record.remotePort=t->remotePort;
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
static GB_ENTRY *injectedEntry(HANDLE id) {
    ULONG i; UINT64 cause=(UINT64)(ULONG_PTR)id;
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i)
        if(gbEntries[i] && gbEntries[i]->record.cause==cause && inboundLayer(gbEntries[i]->record.layerId)) return gbEntries[i];
    return NULL;
}
static BOOLEAN injectionReady(GB_ENTRY *e,UINT64 now) {
    return e && e->injectActive && e->injectPins && e->completing && !e->consumed && !e->revoked && !e->closed &&
        gbFile && !gbFault && e->record.session==gbSession && e->record.loss==gbLoss &&
        e->receipt.decision.revision && e->receipt.decision.scope>=GB_SCOPE_ONCE && e->receipt.decision.scope<=GB_SCOPE_DURATION &&
        (e->receipt.decision.scope!=GB_SCOPE_DURATION || now<e->receipt.deadline);
}
static BOOLEAN injectionMatches(GB_ENTRY *e,void *packet,const GB_TUPLE *t,const FWPS_INCOMING_METADATA_VALUES0 *m) {
    return e && e->packet==packet && sameTuple(e,t) &&
        (m->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) &&
        (m->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID) &&
        m->transportEndpointHandle==e->record.endpoint && m->compartmentId==e->record.compartment;
}
static BOOLEAN applyInboundDecision(GB_ENTRY *e,FWPS_CLASSIFY_OUT0 *out,UINT64 now) {
    if(!injectionReady(e,now) || !((out->rights & FWPS_RIGHT_ACTION_WRITE) ||
        (e->receipt.decision.action==1 && out->actionType==FWP_ACTION_PERMIT)))return FALSE;
    if(e->receipt.decision.action==2)permit(out);else block(out);
    if(out->actionType!=(FWP_ACTION_TYPE)(e->receipt.decision.action==2 ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK))return FALSE;
    e->consumed=TRUE;e->completing=FALSE;e->injectSeen=TRUE;e->receipt.applied=1;
    appliedUtc(e);
    e->receipt.state=GB_SCOPE_APPLIED;e->receipt.observedAt=now;e->receipt.current=1;retireFutureRoots(e);
    return TRUE;
}
static void releasePacket(GB_ENTRY *e,NET_BUFFER_LIST *packet,BOOLEAN failed) {
    KIRQL irql; MDL *mdl; UCHAR *bytes;
    KeAcquireSpinLock(&gbLock,&irql);
    mdl=e->packetMdl; bytes=e->packetBytes; e->packet=NULL; e->packetMdl=NULL; e->packetBytes=NULL;
    if(failed) revoke(e);
    if(e->completing) { revoke(e); e->completing=FALSE; e->consumed=TRUE; }
    KeReleaseSpinLock(&gbLock,irql);
    FwpsFreeNetBufferList0(packet); IoFreeMdl(mdl); ExFreePoolWithTag(bytes,GB_TAG);
    KeAcquireSpinLock(&gbLock,&irql); e->injectActive=FALSE; e->injectQueued=FALSE; --e->injectPins;
    KeReleaseSpinLock(&gbLock,irql);
}
static void NTAPI injectionComplete(void *context,NET_BUFFER_LIST *packet,BOOLEAN dispatchLevel) {
    GB_ENTRY *e=context; UNREFERENCED_PARAMETER(dispatchLevel);
    // Pin propio de completionContext, nunca dereference de injectionContext metadata.
    releasePacket(e,packet,!NT_SUCCESS(NET_BUFFER_LIST_STATUS(packet)));
}
static void NTAPI inboundDpc(KDPC *dpc,void *context,void *a,void *b) {
    GB_ENTRY *e=context; NET_BUFFER_LIST *packet; KIRQL irql; BOOLEAN ready; NTSTATUS status;
    UNREFERENCED_PARAMETER(dpc); UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(b);
    KeAcquireSpinLock(&gbLock,&irql); packet=e->packet; e->injectQueued=FALSE; e->injectActive=TRUE;
    ready=injectionReady(e,KeQueryInterruptTime()); KeReleaseSpinLock(&gbLock,irql);
    if(!ready) { releasePacket(e,packet,TRUE); return; }
    status=FwpsInjectTransportReceiveAsync0(gbInjection[e->record.family==4 ? 0 : 1],
        (HANDLE)(ULONG_PTR)e->record.cause,NULL,0,e->record.family==4 ? AF_INET : AF_INET6,
        e->record.compartment,e->interfaceIndex,e->subInterfaceIndex,packet,injectionComplete,e);
    // SUCCESS sólo inicia; callback puede ejecutarse antes de este return.
    if(!NT_SUCCESS(status)) releasePacket(e,packet,TRUE);
}
static void queueInbound(GB_ENTRY *e,HANDLE completion) {
    KIRQL irql; NET_BUFFER_LIST *packet;
    KeAcquireSpinLock(&gbLock,&irql); packet=e->packet;
    KeReleaseSpinLock(&gbLock,irql);
    FwpsCompleteOperation0(completion,packet);
    if(!KeInsertQueueDpc(&e->injectDpc,NULL,NULL)) releasePacket(e,packet,TRUE);
}
static BOOLEAN packetSpan(UCHAR family,ULONG ipSize,ULONG tcpSize,ULONG offset,ULONG length) {
    if((family!=4 && family!=6) || (family==4 ? ipSize<20 || ipSize>60 || (ipSize&3) : ipSize!=40) ||
        tcpSize<20 || tcpSize>60 || (tcpSize&3))return FALSE;
    return offset>=ipSize+tcpSize && length<=GB_PACKET_BYTES-ipSize-tcpSize;
}
static BOOLEAN packetShape(const GB_ENTRY *e,const UCHAR *ip,ULONG total,ULONG ipSize,ULONG tcpSize) {
    const UCHAR *tcp;UCHAR local[16],remote[16];UINT32 address;
    if(!ip || !packetSpan(e->record.family,ipSize,tcpSize,ipSize+tcpSize,0) ||
        total<ipSize+tcpSize || total>GB_PACKET_BYTES)return FALSE;
    tcp=ip+ipSize;
    RtlCopyMemory(local,e->record.localAddress,16);RtlCopyMemory(remote,e->record.remoteAddress,16);
    if(e->record.family==4) {
        RtlCopyMemory(&address,local,4);address=RtlUlongByteSwap(address);RtlCopyMemory(local,&address,4);
        RtlCopyMemory(&address,remote,4);address=RtlUlongByteSwap(address);RtlCopyMemory(remote,&address,4);
        if((ip[0]>>4)!=4 || (ULONG)(ip[0]&15)*4!=ipSize || ip[9]!=6 ||
            ((ULONG)ip[2]*256+ip[3])!=total || (((ULONG)ip[6]*256+ip[7])&0x3fff) ||
            RtlCompareMemory(ip+12,remote,4)!=4 || RtlCompareMemory(ip+16,local,4)!=4)return FALSE;
    } else if((ip[0]>>4)!=6 || ip[6]!=6 || ((ULONG)ip[4]*256+ip[5])!=total-40 ||
        RtlCompareMemory(ip+8,remote,16)!=16 || RtlCompareMemory(ip+24,local,16)!=16)return FALSE;
    return (ULONG)(tcp[12]>>4)*4==tcpSize && (tcp[13]&2) && !(tcp[13]&0x14) &&
        ((UINT16)tcp[0]*256+tcp[1])==e->record.remotePort && ((UINT16)tcp[2]*256+tcp[3])==e->record.localPort;
}
static BOOLEAN udpSpan(UCHAR family,ULONG ipSize,ULONG udpSize,ULONG offset,ULONG length) {
    if((family!=4 && family!=6) || (family==4 ? ipSize<20 || ipSize>60 || (ipSize&3) : ipSize!=40) || udpSize!=8)return FALSE;
    return offset>=ipSize+udpSize && length<=GB_PACKET_BYTES-ipSize-udpSize;
}
static BOOLEAN udpShape(const GB_ENTRY *e,const UCHAR *ip,ULONG total,ULONG ipSize,ULONG udpSize) {
    const UCHAR *udp;UCHAR local[16],remote[16];UINT32 address;
    if(e->record.protocol!=IPPROTO_UDP || !ip || !udpSpan(e->record.family,ipSize,udpSize,ipSize+udpSize,0) ||
        total<ipSize+udpSize || total>GB_PACKET_BYTES)return FALSE;
    udp=ip+ipSize;RtlCopyMemory(local,e->record.localAddress,16);RtlCopyMemory(remote,e->record.remoteAddress,16);
    if(e->record.family==4) {
        RtlCopyMemory(&address,local,4);address=RtlUlongByteSwap(address);RtlCopyMemory(local,&address,4);
        RtlCopyMemory(&address,remote,4);address=RtlUlongByteSwap(address);RtlCopyMemory(remote,&address,4);
        if((ip[0]>>4)!=4 || (ULONG)(ip[0]&15)*4!=ipSize || ip[9]!=IPPROTO_UDP ||
            ((ULONG)ip[2]*256+ip[3])!=total || (((ULONG)ip[6]*256+ip[7])&0x3fff) ||
            RtlCompareMemory(ip+12,remote,4)!=4 || RtlCompareMemory(ip+16,local,4)!=4)return FALSE;
    } else if((ip[0]>>4)!=6 || ip[6]!=IPPROTO_UDP || ((ULONG)ip[4]*256+ip[5])!=total-40 ||
        RtlCompareMemory(ip+8,remote,16)!=16 || RtlCompareMemory(ip+24,local,16)!=16)return FALSE;
    return ((ULONG)udp[4]*256+udp[5])==total-ipSize &&
        ((UINT16)udp[0]*256+udp[1])==e->record.remotePort && ((UINT16)udp[2]*256+udp[3])==e->record.localPort;
}
static BOOLEAN copyInboundPacket(GB_ENTRY *e,NET_BUFFER_LIST *original,const FWPS_INCOMING_VALUES0 *v,
    const FWPS_INCOMING_METADATA_VALUES0 *m) {
    NET_BUFFER_LIST *clone=NULL; NET_BUFFER *nb; UCHAR *data; ULONG retreat,total,ipSize,tcpSize,ifield,sfield;
    UCHAR local[16],remote[16]; UINT32 address; BOOLEAN retreated=FALSE,ok=FALSE; NTSTATUS status;
    if(!original || NET_BUFFER_LIST_NEXT_NBL(original) || !NET_BUFFER_LIST_FIRST_NB(original) ||
        NET_BUFFER_NEXT_NB(NET_BUFFER_LIST_FIRST_NB(original)) ||
        !(m->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE) ||
        !(m->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE)) return FALSE;
    ipSize=m->ipHeaderSize; tcpSize=m->transportHeaderSize;
    if(!(e->record.protocol==IPPROTO_UDP ? udpSpan(e->record.family,ipSize,tcpSize,GB_PACKET_BYTES,0) :
        packetSpan(e->record.family,ipSize,tcpSize,GB_PACKET_BYTES,0)))return FALSE;
    retreat=ipSize+tcpSize;
    ifield=e->record.family==4 ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_INTERFACE_INDEX : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_INTERFACE_INDEX;
    sfield=e->record.family==4 ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_SUB_INTERFACE_INDEX : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_SUB_INTERFACE_INDEX;
    if(v->valueCount<=sfield || v->incomingValue[ifield].value.type!=FWP_UINT32 || v->incomingValue[sfield].value.type!=FWP_UINT32)return FALSE;
    e->interfaceIndex=v->incomingValue[ifield].value.uint32; e->subInterfaceIndex=v->incomingValue[sfield].value.uint32;
    if(!NT_SUCCESS(FwpsAllocateCloneNetBufferList0(original,NULL,NULL,0,&clone)))return FALSE;
    nb=NET_BUFFER_LIST_FIRST_NB(clone);
    if(!(e->record.protocol==IPPROTO_UDP ? udpSpan(e->record.family,ipSize,tcpSize,NET_BUFFER_DATA_OFFSET(nb),NET_BUFFER_DATA_LENGTH(nb)) :
        packetSpan(e->record.family,ipSize,tcpSize,NET_BUFFER_DATA_OFFSET(nb),NET_BUFFER_DATA_LENGTH(nb))))goto done;
    status=NdisRetreatNetBufferDataStart(nb,retreat,0,NULL); if(!NT_SUCCESS(status))goto done;
    retreated=TRUE; total=NET_BUFFER_DATA_LENGTH(nb);
    e->packetBytes=ExAllocatePool2(POOL_FLAG_NON_PAGED,total,GB_TAG); if(!e->packetBytes)goto done;
    data=NdisGetDataBuffer(nb,total,e->packetBytes,1,0); if(!data)goto done;
    if(data!=e->packetBytes)RtlCopyMemory(e->packetBytes,data,total);
    if(!(e->record.protocol==IPPROTO_UDP ? udpShape(e,e->packetBytes,total,ipSize,tcpSize) :
        packetShape(e,e->packetBytes,total,ipSize,tcpSize)))goto done;
    RtlCopyMemory(local,e->record.localAddress,16);RtlCopyMemory(remote,e->record.remoteAddress,16);
    if(e->record.family==4) {
        RtlCopyMemory(&address,local,4);address=RtlUlongByteSwap(address);RtlCopyMemory(local,&address,4);
        RtlCopyMemory(&address,remote,4);address=RtlUlongByteSwap(address);RtlCopyMemory(remote,&address,4);
    }
    e->packetMdl=IoAllocateMdl(e->packetBytes,total,FALSE,FALSE,NULL);if(!e->packetMdl)goto done;
    MmBuildMdlForNonPagedPool(e->packetMdl);
    if(!NT_SUCCESS(FwpsAllocateNetBufferAndNetBufferList0(gbPacketPool,0,0,e->packetMdl,0,total,&e->packet)))goto done;
    status=FwpsConstructIpHeaderForTransportPacket0(e->packet,ipSize,e->record.family==4 ? AF_INET : AF_INET6,
        remote,local,e->record.protocol,0,NULL,0,0,NULL,e->interfaceIndex,e->subInterfaceIndex);
    ok=NT_SUCCESS(status);
done:
    if(retreated)NdisAdvanceNetBufferDataStart(NET_BUFFER_LIST_FIRST_NB(clone),retreat,FALSE,NULL);
    FwpsFreeCloneNetBufferList0(clone,0); // Ningún parent/MDL de original sobrevive al aviso.
    if(!ok) {
        if(e->packet)FwpsFreeNetBufferList0(e->packet);
        if(e->packetMdl)IoFreeMdl(e->packetMdl);
        if(e->packetBytes)ExFreePoolWithTag(e->packetBytes,GB_TAG);
        e->packet=NULL;e->packetMdl=NULL;e->packetBytes=NULL;
    }
    return ok;
}
static void NTAPI inboundClassify(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data,const void *context,const FWPS_FILTER3 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out) {
    GB_TUPLE t; GB_ENTRY *e,*grant; KIRQL irql; ULONG protocol,flags,empty,i; BOOLEAN ambiguous;
    HANDLE id=NULL,completion=NULL; FWPS_PACKET_INJECTION_STATE state; UINT64 now=KeQueryInterruptTime();
    UNREFERENCED_PARAMETER(context);UNREFERENCED_PARAMETER(flow);
    if(!v || !m || !filter || !inboundLayer(v->layerId)){block(out);return;}
    protocol=v->layerId==FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
    flags=v->layerId==FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS;
    if(v->valueCount<=flags || v->incomingValue[protocol].value.type!=FWP_UINT8 ||
        (v->incomingValue[protocol].value.uint8!=IPPROTO_TCP && v->incomingValue[protocol].value.uint8!=IPPROTO_UDP)) {
        if(out->rights & FWPS_RIGHT_ACTION_WRITE)out->actionType=FWP_ACTION_CONTINUE;return;
    }
    if(v->incomingValue[flags].value.type!=FWP_UINT32 || !tuple(v,m,&t)){block(out);return;}
    state=data ? FwpsQueryPacketInjectionState0(gbInjection[t.family==4 ? 0 : 1],data,&id) : FWPS_PACKET_NOT_INJECTED;
    if(state==FWPS_PACKET_INJECTED_BY_SELF || state==FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
        KeAcquireSpinLock(&gbLock,&irql);e=injectedEntry(id);
        if(injectionMatches(e,data,&t,m) && applyInboundDecision(e,out,now)) {
            // Applied describe sólo esta clasificación del NBL propio.
        } else if(injectionMatches(e,data,&t,m) && e->injectSeen && live(e,now)) {
            if(e->receipt.decision.action==2)permit(out);else block(out);
        } else block(out);
        KeReleaseSpinLock(&gbLock,irql);return;
    }
    if(v->incomingValue[flags].value.uint32 & FWP_CONDITION_FLAG_IS_REAUTHORIZE) {
        KeAcquireSpinLock(&gbLock,&irql);e=endpoint(m,&t,FALSE,TRUE,&ambiguous);
        if(e && !ambiguous && live(e,now) && e->receipt.decision.action==2)permit(out);else block(out);
        KeReleaseSpinLock(&gbLock,irql);return;
    }
    // No presta EP/token del listener ni difiere un handle token a otro hilo.
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL || !(m->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID) ||
        m->compartmentId!=t.compartment || !(m->currentMetadataValues & FWPS_METADATA_FIELD_COMPLETION_HANDLE) ||
        !m->completionHandle || (v->incomingValue[flags].value.uint32 & (FWP_CONDITION_FLAG_IS_RAW_ENDPOINT |
            FWP_CONDITION_FLAG_IS_IPSEC_SECURED | FWP_CONDITION_FLAG_IS_FRAGMENT | FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP |
            FWP_CONDITION_FLAG_IS_IPSEC_NATT_RECLASSIFY | FWP_CONDITION_FLAG_IS_OUTBOUND_PASS_THRU))){block(out);return;}
    e=capture(v,m,filter,&t,0,flags);if(!e){block(out);return;}
    KeInitializeDpc(&e->injectDpc,inboundDpc,e);
    KeAcquireSpinLock(&gbLock,&irql);
    if(!gbFile || gbFault || gbLoss==GB_MAX64 || gbSequence==GB_MAX64)goto reject;
    if(m->currentMetadataValues & FWPS_METADATA_FIELD_PARENT_ENDPOINT_HANDLE)
        for(i=0;i<GB_CLASSIFIER_CAPACITY;++i)if(gbEntries[i] && gbEntries[i]->listener &&
            gbEntries[i]->record.endpoint==m->parentEndpointHandle &&
            (gbEntries[i]->closed || gbEntries[i]->revoked || !sameInstance(gbEntries[i],e)))goto reject;
    empty=slotFor(e,&t,&ambiguous);if(ambiguous || empty==GB_CLASSIFIER_CAPACITY)goto reject;
    grant=futureRoot(e,now,&ambiguous);if(ambiguous)goto reject;
    e->record.session=gbSession;e->record.loss=gbLoss;e->record.cause=++gbSequence;e->pendingDeadline=now+GB_PENDING_TICKS;
    if(grant) {
        e->parent=grant->record.cause;e->receipt=grant->receipt;e->receipt.flow=0;
        e->receipt.decision.cause=e->record.cause;e->consumed=TRUE;e->delivered=TRUE;gbEntries[empty]=e;
        if(e->receipt.decision.action==2)permit(out);else block(out);
        KeReleaseSpinLock(&gbLock,irql);return;
    }
    KeReleaseSpinLock(&gbLock,irql);
    if(!copyInboundPacket(e,data,v,m)){freeEntry(e);block(out);return;}
    if(!currentEntry(e)) {
        FwpsFreeNetBufferList0(e->packet);IoFreeMdl(e->packetMdl);ExFreePoolWithTag(e->packetBytes,GB_TAG);
        freeEntry(e);block(out);return;
    }
    KeAcquireSpinLock(&gbLock,&irql);
    empty=slotFor(e,&t,&ambiguous);
    if(ambiguous || empty==GB_CLASSIFIER_CAPACITY || !gbFile || gbFault || e->record.session!=gbSession || e->record.loss!=gbLoss)goto rejectPacket;
    if(!NT_SUCCESS(FwpsPendOperation0(m->completionHandle,&completion)) || !completion)goto rejectPacket;
    e->completion=completion;e->receipt.state=GB_SCOPE_PENDING;gbEntries[empty]=e;
    block(out);out->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;KeReleaseSpinLock(&gbLock,irql);return;
rejectPacket:
    KeReleaseSpinLock(&gbLock,irql);FwpsFreeNetBufferList0(e->packet);IoFreeMdl(e->packetMdl);ExFreePoolWithTag(e->packetBytes,GB_TAG);
    freeEntry(e);block(out);return;
reject:
    KeReleaseSpinLock(&gbLock,irql);freeEntry(e);block(out);
}
static void NTAPI inboundGuard(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data,const void *context,const FWPS_FILTER3 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out) {
    GB_TUPLE t;GB_ENTRY *e;HANDLE id=NULL;KIRQL irql;ULONG protocol;BOOLEAN ambiguous=FALSE;FWPS_PACKET_INJECTION_STATE state;
    UNREFERENCED_PARAMETER(context);UNREFERENCED_PARAMETER(filter);UNREFERENCED_PARAMETER(flow);
    if(out->rights & FWPS_RIGHT_ACTION_WRITE)out->actionType=FWP_ACTION_CONTINUE;
    if(!v || !m){block(out);return;}
    protocol=v->layerId==FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 ? FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL : FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
    if(v->valueCount<=protocol || v->incomingValue[protocol].value.type!=FWP_UINT8 ||
        (v->incomingValue[protocol].value.uint8!=IPPROTO_TCP && v->incomingValue[protocol].value.uint8!=IPPROTO_UDP))return;
    if(!tuple(v,m,&t)){block(out);return;}
    state=data ? FwpsQueryPacketInjectionState0(gbInjection[t.family==4 ? 0 : 1],data,&id) : FWPS_PACKET_NOT_INJECTED;
    KeAcquireSpinLock(&gbLock,&irql);
    e=(state==FWPS_PACKET_INJECTED_BY_SELF || state==FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) ? injectedEntry(id) : endpoint(m,&t,FALSE,TRUE,&ambiguous);
    if(state==FWPS_PACKET_INJECTED_BY_SELF || state==FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
        if(!injectionMatches(e,data,&t,m) ||
            !(injectionReady(e,KeQueryInterruptTime()) || (e->injectSeen && live(e,KeQueryInterruptTime()))))block(out);
    } else if(ambiguous || (e && (e->cancel.guarded || !live(e,KeQueryInterruptTime()))))block(out);
    KeReleaseSpinLock(&gbLock,irql);
}
static void NTAPI listenerClassify(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data,const void *context,const FWPS_FILTER3 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out) {
    GB_TUPLE t;GB_ENTRY *e;ULONG flags,c,i;KIRQL irql;
    UNREFERENCED_PARAMETER(data);UNREFERENCED_PARAMETER(context);UNREFERENCED_PARAMETER(flow);
    if(out->rights & FWPS_RIGHT_ACTION_WRITE)out->actionType=FWP_ACTION_CONTINUE;
    if(!v || !m || KeGetCurrentIrql()!=PASSIVE_LEVEL)return;
    RtlZeroMemory(&t,sizeof(t));t.family=v->layerId==FWPS_LAYER_ALE_AUTH_LISTEN_V4 ? 4 : 6;t.protocol=IPPROTO_TCP;
    c=t.family==4 ? FWPS_FIELD_ALE_AUTH_LISTEN_V4_COMPARTMENT_ID : FWPS_FIELD_ALE_AUTH_LISTEN_V6_COMPARTMENT_ID;
    flags=t.family==4 ? FWPS_FIELD_ALE_AUTH_LISTEN_V4_FLAGS : FWPS_FIELD_ALE_AUTH_LISTEN_V6_FLAGS;
    if(v->valueCount<=c || v->incomingValue[c].value.type!=FWP_UINT32 || v->incomingValue[4].value.type!=FWP_UINT16 ||
        v->incomingValue[flags].value.type!=FWP_UINT32 || (v->incomingValue[flags].value.uint32 & FWP_CONDITION_FLAG_IS_REAUTHORIZE))return;
    t.compartment=v->incomingValue[c].value.uint32;t.localPort=v->incomingValue[4].value.uint16;
    if(t.family==4) {
        if(v->incomingValue[2].value.type!=FWP_UINT32)return;
        RtlCopyMemory(t.local,&v->incomingValue[2].value.uint32,4);
    } else {
        if(v->incomingValue[2].value.type!=FWP_BYTE_ARRAY16_TYPE || !v->incomingValue[2].value.byteArray16)return;
        RtlCopyMemory(t.local,v->incomingValue[2].value.byteArray16,16);
    }
    e=capture(v,m,filter,&t,0,flags);if(!e)return;e->listener=TRUE;e->delivered=TRUE;
    KeAcquireSpinLock(&gbLock,&irql);
    for(i=0;i<GB_CLASSIFIER_CAPACITY;++i)if(gbEntries[i] && gbEntries[i]->record.endpoint==e->record.endpoint)break;
    if(i==GB_CLASSIFIER_CAPACITY && gbFile && !gbFault && gbSequence!=GB_MAX64) {
        for(i=0;i<GB_CLASSIFIER_CAPACITY;++i)if(!gbEntries[i])break;
        if(i<GB_CLASSIFIER_CAPACITY){e->record.session=gbSession;e->record.loss=gbLoss;e->record.cause=++gbSequence;gbEntries[i]=e;e=NULL;}
    }
    KeReleaseSpinLock(&gbLock,irql);if(e)freeEntry(e);
}
static void NTAPI classify(const FWPS_INCOMING_VALUES0 *v,const FWPS_INCOMING_METADATA_VALUES0 *m,
    void *data,const void *context,const FWPS_FILTER3 *filter,UINT64 flow,FWPS_CLASSIFY_OUT0 *out) {
    ULONG protocolField,flagsField,appField,reasonField,empty=GB_CLASSIFIER_CAPACITY;
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
       (v->incomingValue[protocolField].value.uint8!=IPPROTO_TCP && v->incomingValue[protocolField].value.uint8!=IPPROTO_UDP)) {
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
                appliedUtc(e);
                retireFutureRoots(e);
            }
        }
        if(e && !ambiguous && live(e,now) && e->receipt.decision.action==2) permit(out);
        else block(out);
        KeReleaseSpinLock(&gbLock,irql); return;
    }
    if(v->valueCount<=appField || !(m->currentMetadataValues & FWPS_METADATA_FIELD_COMPLETION_HANDLE) || !m->completionHandle) { block(out); return; }
    e=capture(v,m,filter,&t,appField,flagsField);
    if(!e) {
        // El subset UDP sin owner PASSIVE no invalida grants de otros peers.
        if(t.protocol!=IPPROTO_UDP){KeAcquireSpinLock(&gbLock,&irql);if(gbFile)loss();KeReleaseSpinLock(&gbLock,irql);}
        block(out);return;
    }
    KeAcquireSpinLock(&gbLock,&irql);
    if(!gbFile || gbFault || gbLoss==GB_MAX64 || gbSequence==GB_MAX64) goto deny;
    empty=slotFor(e,&t,&ambiguous);
    if(ambiguous)goto deny;
    grant=futureRoot(e,now,&ambiguous);
    if(ambiguous) { loss(); goto deny; }
    // Saturación simultánea rechaza sólo esta initial; no invalida grants ajenos.
    if(empty==GB_CLASSIFIER_CAPACITY) goto deny;
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
    if(v->valueCount<=flags || v->incomingValue[protocol].value.type!=FWP_UINT8 ||
        (v->incomingValue[protocol].value.uint8!=IPPROTO_TCP && v->incomingValue[protocol].value.uint8!=IPPROTO_UDP)) return;
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
        } else {
            block(out);
            drainDeniedCompletion(e,completion,out->actionType);
        }
    }
    KeReleaseSpinLock(&gbLock,irql);
}
static void maintenance(void *ignored) {
    HANDLE completions[GB_CLASSIFIER_CAPACITY]; UINT64 aborts[GB_CLASSIFIER_CAPACITY];
    GB_ENTRY *packets[GB_CLASSIFIER_CAPACITY]; ULONG np=0;
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
        if(e->revoked && e->packet && !e->injectQueued && !e->injectActive && !e->injectPins) {
            ++e->injectPins;packets[np++]=e;
        }
        if(e->revoked && e->associated && e->receipt.flow) aborts[na++]=e->receipt.flow;
        if(retireable(e)) {
            gbEntries[i]=NULL; discard[nd++]=e;
        }
    }
    KeReleaseSpinLock(&gbLock,irql);
    // Complete/Abort reentran classify/flowDelete: no retener el spinlock.
    for(i=0;i<nc;++i) FwpsCompleteOperation0(completions[i],NULL);
    for(i=0;i<np;++i)releasePacket(packets[i],packets[i]->packet,TRUE);
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
    GB_ENTRY *inboundEffect=NULL,*inboundDiscard=NULL;
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
        } else if(code==GB_CLASSIFIER_ACTIVITY &&
            s->Parameters.DeviceIoControl.InputBufferLength==sizeof(GB_SCOPE_DECISION) &&
            s->Parameters.DeviceIoControl.OutputBufferLength==sizeof(GB_ACTIVITY_SNAPSHOT)) {
            GB_SCOPE_DECISION d;GB_ENTRY *e;
            RtlCopyMemory(&d,irp->AssociatedIrp.SystemBuffer,sizeof(d));status=STATUS_INVALID_PARAMETER;
            if(decisionValid(&d)) {
                KeAcquireSpinLock(&gbLock,&irql);e=byCause(d.session,d.cause);KeReleaseSpinLock(&gbLock,irql);
                status=STATUS_NOT_FOUND;
                if(e) {
                    BOOLEAN identity=currentEntry(e);
                    KeAcquireSpinLock(&gbLock,&irql);
                    if(identity && e->delivered && !e->revoked && !e->closed && !e->parent && e->receipt.applied &&
                       e->record.session==gbSession && e->record.loss==gbLoss &&
                       RtlCompareMemory(&d,&e->receipt.decision,sizeof(d))==sizeof(d)) {
                        GB_ACTIVITY_SNAPSHOT snapshot=e->activity;
                        snapshot.version=GB_ACTIVITY_VERSION;snapshot.bytes=sizeof(snapshot);snapshot.decision=e->receipt.decision;
                        snapshot.loss=e->record.loss;snapshot.flow=e->receipt.flow;
                        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,&snapshot,sizeof(snapshot));
                        bytes=sizeof(snapshot);status=STATUS_SUCCESS;
                    } else status=STATUS_INVALID_CID;
                    KeReleaseSpinLock(&gbLock,irql);
                }
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
                            if(e->packet) { ++e->injectPins;inboundDiscard=e; }
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
                            if(e->packet) { ++e->injectPins;e->injectQueued=TRUE;inboundEffect=e; }
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
    if(inboundEffect)queueInbound(inboundEffect,completion);
    else if(completion) FwpsCompleteOperation0(completion,NULL);
    if(inboundDiscard)releasePacket(inboundDiscard,inboundDiscard->packet,TRUE);
    return finish(irp,status,bytes);
}
static NTSTATUS startClassifier(void) {
    FWPM_SESSION0 session={0}; FWPM_PROVIDER0 provider={0}; FWPM_SUBLAYER0 sublayer={0},*policy=NULL;
    const GUID *layers[GB_CALLOUT_COUNT]={&FWPM_LAYER_ALE_AUTH_CONNECT_V4,&FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &FWPM_LAYER_STREAM_PACKET_V4,&FWPM_LAYER_STREAM_PACKET_V6,&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,&FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4,&FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,&FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        &FWPM_LAYER_ALE_AUTH_LISTEN_V4,&FWPM_LAYER_ALE_AUTH_LISTEN_V6,
        &FWPM_LAYER_DATAGRAM_DATA_V4,&FWPM_LAYER_DATAGRAM_DATA_V6};
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
    {
        NET_BUFFER_LIST_POOL_PARAMETERS parameters={0};
        parameters.Header.Type=NDIS_OBJECT_TYPE_DEFAULT;parameters.Header.Revision=NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        parameters.Header.Size=NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        parameters.fAllocateNetBuffer=TRUE;parameters.PoolTag=GB_TAG;
        gbPacketPool=NdisAllocateNetBufferListPool(NULL,&parameters);
        if(!gbPacketPool){status=STATUS_INSUFFICIENT_RESOURCES;goto fail;}
        status=FwpsInjectionHandleCreate0(AF_INET,FWPS_INJECTION_TYPE_TRANSPORT,&gbInjection[0]);
        if(NT_SUCCESS(status))status=FwpsInjectionHandleCreate0(AF_INET6,FWPS_INJECTION_TYPE_TRANSPORT,&gbInjection[1]);
        if(!NT_SUCCESS(status))goto fail;
    }
    status=PsSetCreateProcessNotifyRoutineEx(processExit,FALSE); if(!NT_SUCCESS(status)) goto fail;
    status=FwpmTransactionBegin0(gbEngine,0); if(!NT_SUCCESS(status)) goto fail;
    provider.providerKey=GbClassifierProvider; provider.displayData.name=L"LGA GateBouncer scoped classifier";
    status=FwpmProviderAdd0(gbEngine,&provider,NULL); if(!NT_SUCCESS(status)) goto abort;
    sublayer.subLayerKey=GbClassifierSublayer; sublayer.providerKey=(GUID *)&GbClassifierProvider;
    sublayer.displayData.name=L"LGA GateBouncer scoped packets"; sublayer.weight=65535;
    status=FwpmSubLayerAdd0(gbEngine,&sublayer,NULL); if(!NT_SUCCESS(status)) goto abort;
    for(i=0;i<GB_CALLOUT_COUNT;++i) {
        FWPS_CALLOUT3 runtime={0}; FWPM_CALLOUT0 callout={0}; FWPM_FILTER0 filter={0}; UINT64 weight=50;
        const GUID *key=i<2 ? &GbClassifierCallouts[i] : i<8 ? &GbScopeCallouts[i-2] :
            i<10 ? &GbHeldGuardCallouts[i-8] : i<16 ? &GbInboundCallouts[i-10] : &GbDatagramCallouts[i-16];
        if((i>=8 && i<10) || (i>=12 && i<14)) weight=1000;
        runtime.calloutKey=*key; runtime.notifyFn=notify;
        runtime.classifyFn=i>=16 ? datagramClassify : i>=14 ? listenerClassify : i>=12 ? inboundGuard : i>=10 ? inboundClassify :
            i>=8 ? heldGuardClassify : i<2 ? classify : i<4 ? packetClassify : i<6 ? establishedClassify : closureClassify;
        if(i==2 || i==3 || i>=16) runtime.flowDeleteFn=flowDelete;
        status=FwpsCalloutRegister3(gbDevice,&runtime,&gbCalloutIds[i]); if(!NT_SUCCESS(status)) goto abort;
        callout.calloutKey=*key; callout.providerKey=(GUID *)&GbClassifierProvider;
        callout.displayData.name=L"LGA GateBouncer scoped traffic"; callout.applicableLayer=*layers[i];
        status=FwpmCalloutAdd0(gbEngine,&callout,NULL,NULL); if(!NT_SUCCESS(status)) goto abort;
        filter.filterKey=i<2 ? GbClassifierFilters[i] : *key; filter.providerKey=(GUID *)&GbClassifierProvider;
        filter.displayData.name=L"LGA GateBouncer scoped traffic"; filter.layerKey=*layers[i];
        filter.subLayerKey=(i<2 || (i>=8 && i<14)) ? GbPolicySublayer : GbClassifierSublayer;
        filter.weight.type=FWP_UINT64; filter.weight.uint64=&weight;
        filter.action.type=(i<4 || (i>=8 && i<14) || i>=16) ? FWP_ACTION_CALLOUT_UNKNOWN : FWP_ACTION_CALLOUT_INSPECTION;
        filter.action.calloutKey=*key;
        status=FwpmFilterAdd0(gbEngine,&filter,NULL,NULL); if(!NT_SUCCESS(status)) goto abort;
    }
    status=FwpmTransactionCommit0(gbEngine); if(!NT_SUCCESS(status)) goto fail;
    gbStarted=TRUE; due.QuadPart=-1000000;
    KeSetTimerEx(&gbTimer,due,100,&gbDpc); return STATUS_SUCCESS;
abort:
    FwpmTransactionAbort0(gbEngine);
fail:
    // Antes de registrar callbacks no existe trabajo ni pins; después retener hasta reboot.
    for(i=0;i<GB_CALLOUT_COUNT;++i)if(gbCalloutIds[i])break;
    if(i==GB_CALLOUT_COUNT) {
        for(i=0;i<2;++i)if(gbInjection[i]){FwpsInjectionHandleDestroy0(gbInjection[i]);gbInjection[i]=NULL;}
        if(gbPacketPool){NdisFreeNetBufferListPool(gbPacketPool);gbPacketPool=NULL;}
    }
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
