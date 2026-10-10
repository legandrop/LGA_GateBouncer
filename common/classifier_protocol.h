#pragma once
// ABI privada del dispositivo; no pertenece a ordinary ni al protocolo IPC.
#define GB_CLASSIFIER_VERSION 1u
#define GB_CLASSIFIER_APP_BYTES 8192u
#define GB_CLASSIFIER_SID_BYTES 68u
#define GB_CLASSIFIER_CAPACITY 64u
#define GB_CLASSIFIER_DEVICE L"\\\\.\\LgaGateBouncerClassifier"
#define GB_CLASSIFIER_NEXT CTL_CODE(FILE_DEVICE_NETWORK, 0x900, METHOD_BUFFERED, FILE_READ_DATA)
#define GB_CLASSIFIER_CURRENT CTL_CODE(FILE_DEVICE_NETWORK, 0x901, METHOD_BUFFERED, FILE_READ_DATA)
#define GB_CLASSIFIER_RELEASE CTL_CODE(FILE_DEVICE_NETWORK, 0x902, METHOD_BUFFERED, FILE_WRITE_DATA)
#define GB_CLASSIFIER_RESET CTL_CODE(FILE_DEVICE_NETWORK, 0x903, METHOD_BUFFERED, FILE_WRITE_DATA)
#define GB_CLASSIFIER_START CTL_CODE(FILE_DEVICE_NETWORK, 0x904, METHOD_BUFFERED, FILE_WRITE_DATA)
static const GUID GbClassifierProvider = {0x6c42ec76,0xc3c3,0x4ac7,{0x98,0x71,0x3e,0x87,0x08,0x65,0x64,0x49}};
static const GUID GbClassifierSublayer = {0x90d88480,0x7796,0x4016,{0x83,0x72,0x7f,0x88,0x8c,0xe7,0xe1,0x80}};
static const GUID GbClassifierCallouts[2] = {
    {0x50f9b010,0x1f9c,0x4d39,{0xbc,0x9f,0x11,0x86,0x9f,0xad,0x01,0x04}},
    {0x50f9b011,0x1f9c,0x4d39,{0xbc,0x9f,0x11,0x86,0x9f,0xad,0x01,0x06}}};
static const GUID GbClassifierFilters[2] = {
    {0xecc11420,0x99bb,0x4d82,{0x8d,0x0a,0x14,0x3f,0x51,0xe0,0x01,0x04}},
    {0xecc11421,0x99bb,0x4d82,{0x8d,0x0a,0x14,0x3f,0x51,0xe0,0x01,0x06}}};
#pragma pack(push, 8)
typedef struct GB_CLASSIFIER_RECORD {
    UINT32 version, bytes;
    UINT64 session, cause, loss, processHandle, pid, created, endpoint, filterId, timestamp;
    UINT32 appBytes, userBytes, flags;
    UINT16 layerId, localPort, remotePort;
    UCHAR family, protocol;
    UCHAR localAddress[16], remoteAddress[16];
    UCHAR user[GB_CLASSIFIER_SID_BYTES], app[GB_CLASSIFIER_APP_BYTES];
} GB_CLASSIFIER_RECORD;
typedef struct GB_CLASSIFIER_QUERY { UINT64 session, cause; } GB_CLASSIFIER_QUERY;
typedef struct GB_CLASSIFIER_STATE { UINT64 session, loss; } GB_CLASSIFIER_STATE;
#pragma pack(pop)
