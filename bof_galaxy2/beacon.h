/*
 * beacon.h – minimal Cobalt Strike BOF header
 * Use the official Cobalt Strike Arsenal Kit version for production.
 */
#pragma once
#include <windows.h>

/* Output callback types */
#define CALLBACK_OUTPUT      0x00
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

/* DLL import shim macro used by BOF API declarations */
#define DECLSPEC_IMPORT __declspec(dllimport)

/* Beacon API (resolved by the BOF loader at runtime) */
DECLSPEC_IMPORT void   BeaconOutput   (int type, char *data, int len);
DECLSPEC_IMPORT void   BeaconPrintf   (int type, char *fmt, ...);
DECLSPEC_IMPORT BOOL   BeaconIsAdmin  (void);
DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char *buffer, int length);
DECLSPEC_IMPORT void   BeaconInjectProcess(DWORD pid, int x86, char *payload, int payload_len, int arg_offset, char *arg, int arg_len);
DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pInfo, char *payload, int payload_len, int arg_offset, char *arg, int arg_len);
DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION *pInfo);
DECLSPEC_IMPORT BOOL   toWideChar(char *src, wchar_t *dst, int max);

/* BeaconData parser helpers */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

DECLSPEC_IMPORT void  BeaconDataParse  (datap *parser, char *buffer, int size);
DECLSPEC_IMPORT char *BeaconDataExtract(datap *parser, int *size);
DECLSPEC_IMPORT int   BeaconDataInt    (datap *parser);
DECLSPEC_IMPORT short BeaconDataShort  (datap *parser);
DECLSPEC_IMPORT int   BeaconDataLength (datap *parser);
