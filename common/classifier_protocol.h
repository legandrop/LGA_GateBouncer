#pragma once
// ABI privada del dispositivo; no pertenece a ordinary ni al protocolo IPC.
#define GB_CLASSIFIER_VERSION 2u
#define GB_CLASSIFIER_APP_BYTES 8192u
#define GB_CLASSIFIER_SID_BYTES 68u
#define GB_CLASSIFIER_CAPACITY 64u
// Capacidad conjunta de operaciones y tombstones retenidos por endpoint OS.
#define GB_CLASSIFIER_DEVICE L"\\\\.\\LgaGateBouncerClassifier"
#define GB_CLASSIFIER_NEXT CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_READ_DATA)
#define GB_CLASSIFIER_CURRENT CTL_CODE(FILE_DEVICE_NETWORK, 0x901, METHOD_BUFFERED, FILE_READ_DATA)
#define GB_CLASSIFIER_RELEASE CTL_CODE(FILE_DEVICE_NETWORK, 0x902, METHOD_BUFFERED, FILE_WRITE_DATA)
#define GB_CLASSIFIER_RESET CTL_CODE(FILE_DEVICE_NETWORK, 0x903, METHOD_BUFFERED, FILE_WRITE_DATA)
#define GB_CLASSIFIER_START CTL_CODE(FILE_DEVICE_NETWORK, 0x904, METHOD_BUFFERED, FILE_WRITE_DATA)
#define GB_CLASSIFIER_DECIDE CTL_CODE(FILE_DEVICE_NETWORK, 0x905, METHOD_BUFFERED, FILE_WRITE_DATA)
#define GB_CLASSIFIER_READBACK CTL_CODE(FILE_DEVICE_NETWORK, 0x906, METHOD_BUFFERED, FILE_READ_DATA)
#define GB_CLASSIFIER_CANCEL CTL_CODE(FILE_DEVICE_NETWORK, 0x907, METHOD_BUFFERED, FILE_WRITE_DATA)
#define GB_CLASSIFIER_CANCEL_READBACK CTL_CODE(FILE_DEVICE_NETWORK, 0x908, METHOD_BUFFERED, FILE_READ_DATA)
#define GB_SCOPE_ONCE 3u
#define GB_SCOPE_INSTANCE 4u
#define GB_SCOPE_DURATION 5u
#define GB_SCOPE_PENDING 1u
#define GB_SCOPE_COMPLETING 2u
#define GB_SCOPE_APPLIED 3u
#define GB_SCOPE_REVOKED 4u
#define GB_SCOPE_CLOSED 5u
#define GB_SCOPE_MAX_MS 900000u
static const GUID GbPolicyProvider = {0xeec4d47a,0x91a5,0x4f6c,{0xba,0x34,0xb1,0xc7,0x8d,0xaa,0x82,0x31}};
static const GUID GbPolicySublayer = {0xa80c1782,0x61a7,0x4499,{0xb7,0x96,0x5a,0x3d,0x3a,0x28,0x22,0x39}};
static const GUID GbClassifierProvider = {0x6c42ec76,0xc3c3,0x4ac7,{0x98,0x71,0x3e,0x87,0x08,0x65,0x64,0x49}};
static const GUID GbClassifierSublayer = {0x90d88480,0x7796,0x4016,{0x83,0x72,0x7f,0x88,0x8c,0xe7,0xe1,0x80}};
static const GUID GbClassifierCallouts[2] = {
    {0x50f9b010,0x1f9c,0x4d39,{0xbc,0x9f,0x11,0x86,0x9f,0xad,0x01,0x04}},
    {0x50f9b011,0x1f9c,0x4d39,{0xbc,0x9f,0x11,0x86,0x9f,0xad,0x01,0x06}}};
static const GUID GbClassifierFilters[2] = {
    {0xecc11420,0x99bb,0x4d82,{0x8d,0x0a,0x14,0x3f,0x51,0xe0,0x01,0x04}},
    {0xecc11421,0x99bb,0x4d82,{0x8d,0x0a,0x14,0x3f,0x51,0xe0,0x01,0x06}}};
static const GUID GbScopeCallouts[6] = {
 {0x50f9b012,0x1f9c,0x4d39,{0xbc,0x9f,0x11,0x86,0x9f,0xad,1,4}},
 {0x50f9b013,0x1f9c,0x4d39,{0xbc,0x9f,0x11,0x86,0x9f,0xad,1,6}},
 {0x50f9b014,0x1f9c,0x4d39,{0xbc,0x9f,0x11,0x86,0x9f,0xad,1,4}},
 {0x50f9b015,0x1f9c,0x4d39,{0xbc,0x9f,0x11,0x86,0x9f,0xad,1,6}},
 {0x50f9b016,0x1f9c,0x4d39,{0xbc,0x9f,0x11,0x86,0x9f,0xad,1,4}},
 {0x50f9b017,0x1f9c,0x4d39,{0xbc,0x9f,0x11,0x86,0x9f,0xad,1,6}}};
static const GUID GbHeldGuardCallouts[2] = {
 {0x50f9b018,0x1f9c,0x4d39,{0xbc,0x9f,0x11,0x86,0x9f,0xad,1,4}},
 {0x50f9b019,0x1f9c,0x4d39,{0xbc,0x9f,0x11,0x86,0x9f,0xad,1,6}}};
#pragma pack(push, 8)
typedef struct GB_CLASSIFIER_RECORD {
    UINT32 version, bytes;
    UINT64 session, cause, loss, processHandle, pid, created, endpoint, filterId, timestamp;
    UINT32 appBytes, userBytes, flags, compartment;
    UINT16 layerId, localPort, remotePort;
    UCHAR family, protocol;
    UCHAR localAddress[16], remoteAddress[16];
    UCHAR user[GB_CLASSIFIER_SID_BYTES], app[GB_CLASSIFIER_APP_BYTES];
} GB_CLASSIFIER_RECORD;
typedef struct GB_CLASSIFIER_QUERY { UINT64 session, cause; } GB_CLASSIFIER_QUERY;
typedef struct GB_CLASSIFIER_STATE { UINT64 session, loss; } GB_CLASSIFIER_STATE;
typedef struct GB_SCOPE_DECISION {
    UINT32 version, bytes;
    UINT64 session, cause, revision;
    UCHAR command[16];
    UINT32 scope, action, durationMs, reserved;
} GB_SCOPE_DECISION;
typedef struct GB_SCOPE_RECEIPT {
    GB_SCOPE_DECISION decision;
    UINT64 deadline, flow, observedAt;
    UINT32 state, applied, current, reserved;
} GB_SCOPE_RECEIPT;
// guarded prueba guard negativo retenido, no es ACK de CompleteOperation.
typedef struct GB_CANCEL_RECEIPT {
    GB_SCOPE_DECISION decision;
    UINT64 deniedAt;
    UINT32 guarded, closed, reauthDenied, reserved;
} GB_CANCEL_RECEIPT;
#pragma pack(pop)
