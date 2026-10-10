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
// Contrato WinNT.h del SDK: los headers km no exponen estos nombres usermode.
#define GB_GROUP_ENABLED 0x00000004L
#define GB_GROUP_DENY_ONLY 0x00000010L
#define GB_PROCESS_QUERY_LIMITED 0x1000
typedef struct GB_ENTRY {
    LIST_ENTRY link;
    GB_CLASSIFIER_RECORD record;
    PEPROCESS process;
    PACCESS_TOKEN token;
    BOOLEAN delivered;
} GB_ENTRY;
static EX_PUSH_LOCK gbLock;
static LIST_ENTRY gbQueue;
static UINT32 gbCount, gbCalloutIds[2];
static UINT64 gbSession, gbSequence, gbLoss;
static PFILE_OBJECT gbFile;
static PEPROCESS gbOwner;
static PDEVICE_OBJECT gbDevice;
static HANDLE gbEngine;
static BOOLEAN gbStarted, gbFault;
static UNICODE_STRING gbLink = RTL_CONSTANT_STRING(L"\\DosDevices\\LgaGateBouncerClassifier");
static NTSTATUS startClassifier(void);

static void lockQueue(void) { KeEnterCriticalRegion(); ExAcquirePushLockExclusive(&gbLock); }
static void unlockQueue(void) { ExReleasePushLockExclusive(&gbLock); KeLeaveCriticalRegion(); }
static void freeEntry(GB_ENTRY *e) {
    if (e->token) PsDereferencePrimaryToken(e->token);
    if (e->process) ObDereferenceObject(e->process);
    ExFreePoolWithTag(e, GB_TAG);
}
static void clearQueue(void) {
    while (!IsListEmpty(&gbQueue)) {
        GB_ENTRY *e = CONTAINING_RECORD(RemoveHeadList(&gbQueue), GB_ENTRY, link);
        freeEntry(e);
    }
    gbCount = 0;
}
static BOOLEAN serviceOwner(void) {
    PACCESS_TOKEN token=PsReferencePrimaryToken(PsGetCurrentProcess());
    PTOKEN_USER user=NULL; PTOKEN_GROUPS groups=NULL; BOOLEAN accepted=FALSE;
    SID_IDENTIFIER_AUTHORITY authority=SECURITY_NT_AUTHORITY;
    UCHAR storage[SECURITY_MAX_SID_SIZE]; PSID service=(PSID)storage; ULONG i;
    // SID determinista del servicio LGAGateBouncerLab; misma identidad exigida en usermode.
    RtlInitializeSid(service,&authority,6);
    *RtlSubAuthoritySid(service,0)=SECURITY_SERVICE_ID_BASE_RID;
    *RtlSubAuthoritySid(service,1)=261359355; *RtlSubAuthoritySid(service,2)=3591545304;
    *RtlSubAuthoritySid(service,3)=103058424; *RtlSubAuthoritySid(service,4)=11622622;
    *RtlSubAuthoritySid(service,5)=265084995;
    if (NT_SUCCESS(SeQueryInformationToken(token,TokenUser,(PVOID *)&user)) && user &&
        RtlEqualSid(user->User.Sid,SeExports->SeLocalSystemSid) &&
        NT_SUCCESS(SeQueryInformationToken(token,TokenGroups,(PVOID *)&groups)) && groups) {
        for (i=0;i<groups->GroupCount;++i)
            if ((groups->Groups[i].Attributes & GB_GROUP_ENABLED) &&
                !(groups->Groups[i].Attributes & GB_GROUP_DENY_ONLY) &&
                RtlEqualSid(groups->Groups[i].Sid,service)) { accepted=TRUE; break; }
    }
    if (user) ExFreePool(user); if (groups) ExFreePool(groups);
    PsDereferencePrimaryToken(token); return accepted;
}
static BOOLEAN currentEntry(GB_ENTRY *e) {
    PACCESS_TOKEN fresh;
    BOOLEAN same;
    if (PsGetProcessExitStatus(e->process) != STATUS_PENDING ||
        (UINT64)PsGetProcessCreateTimeQuadPart(e->process) != e->record.created) return FALSE;
    fresh = PsReferencePrimaryToken(e->process);
    same = fresh == e->token;
    PsDereferencePrimaryToken(fresh);
    return same;
}
static void NTAPI classify(const FWPS_INCOMING_VALUES0 *v,
    const FWPS_INCOMING_METADATA_VALUES0 *m, void *layerData,
    const void *classifyContext, const FWPS_FILTER3 *filter,
    UINT64 flowContext, FWPS_CLASSIFY_OUT0 *out) {
    GB_ENTRY *e;
    FWP_BYTE_BLOB *app;
    PTOKEN_USER user = NULL;
    PULONG container = NULL;
    ULONG protocolField, flagsField, appField, localField, remoteField, localPortField, remotePortField;
    LARGE_INTEGER now;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(layerData); UNREFERENCED_PARAMETER(classifyContext); UNREFERENCED_PARAMETER(flowContext);
    // Inspection no concede ni veta: sin ACTION_WRITE conserva la acción del OS.
    if (!(out->rights & FWPS_RIGHT_ACTION_WRITE)) return;
    out->actionType = FWP_ACTION_CONTINUE;
    // PsLookup/token query son PASSIVE aquí. Nunca encolar PID para resolverlo después.
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || !v || !m || !filter ||
        !(m->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) ||
        !(m->currentMetadataValues & FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) ||
        !(m->currentMetadataValues & FWPS_METADATA_FIELD_TOKEN) || !m->token ||
        !m->processId || !m->transportEndpointHandle ||
        (UINT64)(ULONG_PTR)PsGetProcessId(PsGetCurrentProcess()) != m->processId) return;
    if (v->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        protocolField=FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL; flagsField=FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS;
        appField=FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID; localField=FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
        remoteField=FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
        localPortField=FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT; remotePortField=FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
    } else if (v->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) {
        protocolField=FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL; flagsField=FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS;
        appField=FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID; localField=FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
        remoteField=FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
        localPortField=FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT; remotePortField=FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
    } else return;
    if (v->valueCount <= remotePortField || v->valueCount <= flagsField ||
        v->incomingValue[protocolField].value.type != FWP_UINT8 ||
        v->incomingValue[protocolField].value.uint8 != 6 ||
        v->incomingValue[flagsField].value.type != FWP_UINT32 ||
        (v->incomingValue[flagsField].value.uint32 &
            (FWP_CONDITION_FLAG_IS_REAUTHORIZE | FWP_CONDITION_FLAG_IS_RAW_ENDPOINT)) ||
        v->incomingValue[appField].value.type != FWP_BYTE_BLOB_TYPE) return;
    app = v->incomingValue[appField].value.byteBlob;
    if (!app || !app->data || app->size < 4 || app->size > GB_CLASSIFIER_APP_BYTES || (app->size & 1)) return;
    e = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*e), GB_TAG);
    if (!e) { lockQueue(); if (gbFile && gbLoss != GB_MAX64) ++gbLoss; unlockQueue(); return; }
    RtlZeroMemory(e, sizeof(*e));
    // Vertical síncrona: sólo el contexto proceso que coincide con endpoint-owner.
    // Referencia el objeto actual; un PID guardado jamás se vuelve a resolver.
    e->process=PsGetCurrentProcess(); ObReferenceObject(e->process);
    e->token = PsReferencePrimaryToken(e->process);
    {
        PACCESS_TOKEN endpointToken=NULL;
        status=ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)m->token,TOKEN_QUERY,*SeTokenObjectType,
            KernelMode,(PVOID *)&endpointToken,NULL);
        if (!NT_SUCCESS(status) || endpointToken != e->token) {
            if (endpointToken) ObDereferenceObject(endpointToken);
            goto done;
        }
        ObDereferenceObject(endpointToken);
    }
    status = SeQueryInformationToken(e->token, TokenIsAppContainer, (PVOID *)&container);
    if (!NT_SUCCESS(status) || !container || *container) goto done;
    ExFreePool(container); container = NULL;
    status = SeQueryInformationToken(e->token, TokenUser, (PVOID *)&user);
    if (!NT_SUCCESS(status) || !user || !RtlValidSid(user->User.Sid) ||
        RtlLengthSid(user->User.Sid) > GB_CLASSIFIER_SID_BYTES) goto done;
    e->record.version=GB_CLASSIFIER_VERSION; e->record.bytes=sizeof(e->record);
    e->record.pid=m->processId; e->record.created=(UINT64)PsGetProcessCreateTimeQuadPart(e->process);
    e->record.endpoint=m->transportEndpointHandle; e->record.filterId=filter->filterId; e->record.layerId=v->layerId;
    e->record.flags=v->incomingValue[flagsField].value.uint32;
    e->record.family=v->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4 ? 4 : 6; e->record.protocol=6;
    e->record.appBytes=app->size; RtlCopyMemory(e->record.app, app->data, app->size);
    e->record.userBytes=RtlLengthSid(user->User.Sid); RtlCopyMemory(e->record.user, user->User.Sid, e->record.userBytes);
    if (v->incomingValue[localPortField].value.type != FWP_UINT16 ||
        v->incomingValue[remotePortField].value.type != FWP_UINT16) goto done;
    e->record.localPort=v->incomingValue[localPortField].value.uint16;
    e->record.remotePort=v->incomingValue[remotePortField].value.uint16;
    if (e->record.family == 4) {
        if (v->incomingValue[localField].value.type != FWP_UINT32 || v->incomingValue[remoteField].value.type != FWP_UINT32) goto done;
        RtlCopyMemory(e->record.localAddress, &v->incomingValue[localField].value.uint32, 4);
        RtlCopyMemory(e->record.remoteAddress, &v->incomingValue[remoteField].value.uint32, 4);
    } else {
        if (v->incomingValue[localField].value.type != FWP_BYTE_ARRAY16_TYPE ||
            v->incomingValue[remoteField].value.type != FWP_BYTE_ARRAY16_TYPE ||
            !v->incomingValue[localField].value.byteArray16 || !v->incomingValue[remoteField].value.byteArray16) goto done;
        RtlCopyMemory(e->record.localAddress, v->incomingValue[localField].value.byteArray16, 16);
        RtlCopyMemory(e->record.remoteAddress, v->incomingValue[remoteField].value.byteArray16, 16);
    }
    KeQuerySystemTimePrecise(&now); e->record.timestamp=(UINT64)now.QuadPart;
    lockQueue();
    if (!gbFile || gbFault || !currentEntry(e)) { unlockQueue(); goto done; }
    if (gbCount == GB_CLASSIFIER_CAPACITY || gbSequence == GB_MAX64 || gbLoss == GB_MAX64) {
        if (gbLoss != GB_MAX64) ++gbLoss;
        unlockQueue(); goto done;
    }
    e->record.session=gbSession; e->record.cause=++gbSequence; e->record.loss=gbLoss;
    InsertTailList(&gbQueue, &e->link); ++gbCount; e=NULL;
    unlockQueue();
done:
    if (user) ExFreePool(user);
    if (container) ExFreePool(container);
    if (e) freeEntry(e);
}
static NTSTATUS NTAPI notify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID *key, FWPS_FILTER3 *filter) {
    UNREFERENCED_PARAMETER(type); UNREFERENCED_PARAMETER(key); UNREFERENCED_PARAMETER(filter); return STATUS_SUCCESS;
}
static NTSTATUS finish(PIRP irp, NTSTATUS status, ULONG_PTR bytes) {
    irp->IoStatus.Status=status; irp->IoStatus.Information=bytes; IoCompleteRequest(irp, IO_NO_INCREMENT); return status;
}
static NTSTATUS NTAPI dispatch(PDEVICE_OBJECT device, PIRP irp) {
    PIO_STACK_LOCATION s=IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status=STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR bytes=0;
    UINT32 code;
    UNREFERENCED_PARAMETER(device);
    // Cleanup/Close también pueden llegar desde el worker del I/O manager.
    if (s->MajorFunction == IRP_MJ_CLEANUP && KeGetCurrentIrql() == PASSIVE_LEVEL) {
        lockQueue();
        if (s->FileObject == gbFile) {
            clearQueue(); gbFile=NULL; ObDereferenceObject(gbOwner); gbOwner=NULL;
        }
        unlockQueue(); return finish(irp, STATUS_SUCCESS, 0);
    }
    if (s->MajorFunction == IRP_MJ_CLOSE) return finish(irp, STATUS_SUCCESS, 0);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || irp->RequestorMode != UserMode ||
        PsGetCurrentProcess() != IoGetRequestorProcess(irp)) return finish(irp, STATUS_ACCESS_DENIED, 0);
    lockQueue();
    if (s->MajorFunction == IRP_MJ_CREATE) {
        // Device ACL es SY solamente; file/object del servicio retenidos hasta cleanup.
        if (!gbFile && gbSession != GB_MAX64 && serviceOwner()) {
            gbFile=s->FileObject; gbOwner=PsGetCurrentProcess(); ObReferenceObject(gbOwner);
            ++gbSession; clearQueue(); gbLoss=0; status=STATUS_SUCCESS;
        } else status=STATUS_SHARING_VIOLATION;
    } else if (s->MajorFunction == IRP_MJ_DEVICE_CONTROL && s->FileObject == gbFile && PsGetCurrentProcess() == gbOwner && serviceOwner()) {
        code=s->Parameters.DeviceIoControl.IoControlCode;
        if (code == GB_CLASSIFIER_START && s->Parameters.DeviceIoControl.InputBufferLength == 0 &&
            s->Parameters.DeviceIoControl.OutputBufferLength == 0) {
            status=startClassifier();
        } else if (gbFault || !gbStarted) status=STATUS_DEVICE_NOT_READY;
        else if (code == GB_CLASSIFIER_RESET && s->Parameters.DeviceIoControl.InputBufferLength == 0 &&
            s->Parameters.DeviceIoControl.OutputBufferLength == sizeof(GB_CLASSIFIER_STATE)) {
            GB_CLASSIFIER_STATE *state=irp->AssociatedIrp.SystemBuffer;
            clearQueue(); state->session=gbSession; state->loss=gbLoss; bytes=sizeof(*state); status=STATUS_SUCCESS;
        } else if (code == GB_CLASSIFIER_NEXT && s->Parameters.DeviceIoControl.InputBufferLength == 0 &&
            s->Parameters.DeviceIoControl.OutputBufferLength == sizeof(GB_CLASSIFIER_RECORD)) {
            PLIST_ENTRY item;
            status=STATUS_NO_MORE_ENTRIES;
            for (item=gbQueue.Flink; item != &gbQueue; item=item->Flink) {
                GB_ENTRY *e=CONTAINING_RECORD(item, GB_ENTRY, link);
                HANDLE handle=NULL;
                if (e->delivered) continue;
                if (!currentEntry(e) || e->record.loss != gbLoss) { e->delivered=TRUE; continue; }
                // Abre el objeto ya referenciado en la tabla del caller, nunca mediante PID.
                status=ObOpenObjectByPointer(e->process, 0, NULL, GB_PROCESS_QUERY_LIMITED|SYNCHRONIZE,
                    *PsProcessType, KernelMode, &handle);
                if (!NT_SUCCESS(status)) break;
                e->record.processHandle=(UINT64)(ULONG_PTR)handle; e->delivered=TRUE;
                RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &e->record, sizeof(e->record));
                bytes=sizeof(e->record); break;
            }
            if (status == STATUS_NO_MORE_ENTRIES && gbLoss) status=STATUS_DATA_ERROR;
        } else if ((code == GB_CLASSIFIER_CURRENT || code == GB_CLASSIFIER_RELEASE) &&
            s->Parameters.DeviceIoControl.InputBufferLength == sizeof(GB_CLASSIFIER_QUERY) &&
            s->Parameters.DeviceIoControl.OutputBufferLength == 0) {
            GB_CLASSIFIER_QUERY *q=irp->AssociatedIrp.SystemBuffer;
            PLIST_ENTRY item;
            status=STATUS_NOT_FOUND;
            for (item=gbQueue.Flink; item != &gbQueue; item=item->Flink) {
                GB_ENTRY *e=CONTAINING_RECORD(item, GB_ENTRY, link);
                if (q->session != gbSession || q->cause != e->record.cause || !e->delivered) continue;
                if (code == GB_CLASSIFIER_RELEASE) { RemoveEntryList(item); --gbCount; freeEntry(e); status=STATUS_SUCCESS; }
                else status=e->record.loss == gbLoss && currentEntry(e) ? STATUS_SUCCESS : STATUS_INVALID_CID;
                break;
            }
        }
    }
    unlockQueue();
    return finish(irp, status, bytes);
}
static NTSTATUS startClassifier(void) {
    FWPM_SESSION0 session={0}; FWPM_PROVIDER0 provider={0}; FWPM_SUBLAYER0 sublayer={0};
    const GUID *layers[2]={&FWPM_LAYER_ALE_AUTH_CONNECT_V4,&FWPM_LAYER_ALE_AUTH_CONNECT_V6};
    NTSTATUS status; UINT32 i;
    if (gbFault) return STATUS_DEVICE_NOT_READY;
    if (gbStarted) return STATUS_SUCCESS;
    // Sólo se registra después de DriverEntry exitoso, con la imagen ya fijada.
    // Fallos parciales conservan handles/IDs y código vivo hasta reboot.
    session.flags=FWPM_SESSION_FLAG_DYNAMIC;
    status=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,&session,&gbEngine); if (!NT_SUCCESS(status)) goto fail;
    status=FwpmTransactionBegin0(gbEngine,0); if (!NT_SUCCESS(status)) goto fail;
    provider.providerKey=GbClassifierProvider; provider.displayData.name=L"LGA GateBouncer classifier";
    status=FwpmProviderAdd0(gbEngine,&provider,NULL); if (!NT_SUCCESS(status)) goto abort;
    sublayer.subLayerKey=GbClassifierSublayer; sublayer.providerKey=(GUID *)&GbClassifierProvider;
    sublayer.displayData.name=L"LGA GateBouncer classifier"; sublayer.weight=65535;
    status=FwpmSubLayerAdd0(gbEngine,&sublayer,NULL); if (!NT_SUCCESS(status)) goto abort;
    for (i=0;i<2;++i) {
        FWPS_CALLOUT3 runtime={0}; FWPM_CALLOUT0 callout={0}; FWPM_FILTER0 filter={0};
        runtime.calloutKey=GbClassifierCallouts[i]; runtime.classifyFn=classify; runtime.notifyFn=notify;
        status=FwpsCalloutRegister3(gbDevice,&runtime,&gbCalloutIds[i]); if (!NT_SUCCESS(status)) goto abort;
        callout.calloutKey=GbClassifierCallouts[i]; callout.providerKey=(GUID *)&GbClassifierProvider;
        callout.displayData.name=L"LGA GateBouncer TCP initial cause"; callout.applicableLayer=*layers[i];
        status=FwpmCalloutAdd0(gbEngine,&callout,NULL,NULL); if (!NT_SUCCESS(status)) goto abort;
        filter.filterKey=GbClassifierFilters[i]; filter.providerKey=(GUID *)&GbClassifierProvider;
        filter.displayData.name=L"LGA GateBouncer TCP initial cause"; filter.layerKey=*layers[i];
        filter.subLayerKey=GbClassifierSublayer; filter.weight.type=FWP_EMPTY;
        filter.action.type=FWP_ACTION_CALLOUT_INSPECTION; filter.action.calloutKey=GbClassifierCallouts[i];
        status=FwpmFilterAdd0(gbEngine,&filter,NULL,NULL); if (!NT_SUCCESS(status)) goto abort;
    }
    status=FwpmTransactionCommit0(gbEngine); if (!NT_SUCCESS(status)) goto fail;
    gbStarted=TRUE;
    return STATUS_SUCCESS;
abort:
    FwpmTransactionAbort0(gbEngine);
fail:
    gbFault=TRUE; return status;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry) {
    UNICODE_STRING deviceName=RTL_CONSTANT_STRING(L"\\Device\\LgaGateBouncerClassifier");
    UNICODE_STRING security=RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)");
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registry);
    ExInitializePushLock(&gbLock); InitializeListHead(&gbQueue);
    driver->MajorFunction[IRP_MJ_CREATE]=dispatch; driver->MajorFunction[IRP_MJ_CLEANUP]=dispatch;
    driver->MajorFunction[IRP_MJ_CLOSE]=dispatch; driver->MajorFunction[IRP_MJ_DEVICE_CONTROL]=dispatch;
    // Corte inicial sin descarga dinámica: no permite ejecutar callbacks sobre
    // una imagen descargada. Reboot es requerido para retirar esta imagen.
    driver->DriverUnload=NULL;
    status=IoCreateDeviceSecure(driver,0,&deviceName,FILE_DEVICE_NETWORK,FILE_DEVICE_SECURE_OPEN,FALSE,
        &security,&GbClassifierProvider,&gbDevice);
    if (!NT_SUCCESS(status)) return status;
    status=IoCreateSymbolicLink(&gbLink,&deviceName);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(gbDevice); gbDevice=NULL; return status; }
    // DriverEntry no creó ni un callout: sus fallos siempre son descargables.
    gbDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
