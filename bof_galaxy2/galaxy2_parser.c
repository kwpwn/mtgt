/*
 * galaxy2_parser.c  –  BOF: parse E:\galaxy2.dat → pretty JSON
 *
 * File layout (discovered by reversing the binary):
 *   [FILE HEADER – 100 bytes]
 *     0x00 DWORD  version       (= 2)
 *     0x04 DWORD  record_count  (= 105)
 *     0x08 …      zeros padding
 *
 *   [RECORD] × record_count
 *     0x00 DWORD   body_size   (= total_record_bytes – 4)
 *     0x04 QWORD   timestamp   (100-ns ticks, likely QPC since boot)
 *     0x0C DWORD   reserved0
 *     0x10 DWORD   field1      (constant 0x800 across file)
 *     0x14 QWORD   field2      (kernel address / LUID)
 *     0x1C DWORD   pid1
 *     0x20 DWORD   pid2
 *     0x24 DWORD   pid3
 *     0x28 DWORD   record_id
 *     0x2C BYTE    pad         (alignment)
 *     0x2D …       UTF-16LE null-terminated pipe-delimited string
 *                  format: |Key:Value|Key:Value|…|\x01\x00\x00
 *
 *   Pipe-delimited fields found in this file:
 *     Block, Prompt, AutoProc, UserAction,
 *     Path, PPath, CmdLine, PCmdLine
 *   Values may contain Chinese (Traditional/Simplified) text.
 *
 * Compile (MinGW-w64):
 *   x86_64-w64-mingw32-gcc -o galaxy2_parser.o -c galaxy2_parser.c \
 *       -Wall -masm=intel -fno-asynchronous-unwind-tables
 *
 * Compile (MSVC):
 *   cl /c /GS- /Zl /W3 galaxy2_parser.c
 *
 * Load in Cobalt Strike CNA:
 *   inline-execute galaxy2_parser.o
 */

#include <windows.h>
#include "beacon.h"

/* ── Win32 API imports (BOF-style) ─────────────────────────────────────────── */

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplate);

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileSize(
    HANDLE hFile, LPDWORD lpFileSizeHigh);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(
    HANDLE hFile, LPVOID lpBuffer, DWORD nBytesToRead,
    LPDWORD lpBytesRead, LPOVERLAPPED lpOverlapped);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(
    HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(
    HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(
    UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar,
    LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar,
    LPBOOL lpUsedDefaultChar);

/* ── Constants ──────────────────────────────────────────────────────────────── */

#define MY_HEAP_ZERO_MEMORY  0x00000008u
#define FILE_HEADER_SIZE     100u
#define RECORD_HDR_SIZE      45u    /* 4 (body_size DWORD) + 41 metadata bytes */
#define RECORD_META_AFTER_SZ 41u    /* bytes between body_size and string start */

/* ── Inline string/buffer helpers (no CRT) ──────────────────────────────────── */

static int buf_app(char *b, int pos, int cap, const char *s) {
    while (*s && pos < cap - 1) b[pos++] = *s++;
    return pos;
}

static int buf_appn(char *b, int pos, int cap, const char *s, int n) {
    while (n-- > 0 && pos < cap - 1) b[pos++] = *s++;
    return pos;
}

/* Append unsigned 64-bit integer as decimal digits */
static int buf_u64(char *b, int pos, int cap, ULONGLONG v) {
    char tmp[22];
    int n = 0;
    if (v == 0) { tmp[n++] = '0'; }
    else { while (v) { tmp[n++] = (char)('0' + (int)(v % 10)); v /= 10; } }
    /* reverse in-place */
    for (int i = 0, j = n - 1; i < j; i++, j--) {
        char t = tmp[i]; tmp[i] = tmp[j]; tmp[j] = t;
    }
    return buf_appn(b, pos, cap, tmp, n);
}

/*
 * Emit a JSON-escaped UTF-8 string (including surrounding double-quotes).
 * Multi-byte UTF-8 sequences (e.g. Chinese) are passed through unchanged;
 * only ASCII control chars and JSON meta-chars are escaped.
 */
static int buf_json_u8(char *b, int pos, int cap, const char *s) {
    pos = buf_app(b, pos, cap, "\"");
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if      (c == '"')  { pos = buf_app(b, pos, cap, "\\\""); }
        else if (c == '\\') { pos = buf_app(b, pos, cap, "\\\\"); }
        else if (c == '\n') { pos = buf_app(b, pos, cap, "\\n");  }
        else if (c == '\r') { pos = buf_app(b, pos, cap, "\\r");  }
        else if (c == '\t') { pos = buf_app(b, pos, cap, "\\t");  }
        else if (c < 0x20) {
            /* \u00XX escape for other ASCII controls */
            const char *hx = "0123456789abcdef";
            char esc[7];
            esc[0] = '\\'; esc[1] = 'u';
            esc[2] = '0';  esc[3] = '0';
            esc[4] = hx[(c >> 4) & 0xF];
            esc[5] = hx[c & 0xF];
            esc[6] = '\0';
            pos = buf_app(b, pos, cap, esc);
        } else {
            if (pos < cap - 1) b[pos++] = (char)c;
        }
    }
    pos = buf_app(b, pos, cap, "\"");
    return pos;
}

/*
 * Convert a wchar_t span (length wlen, NOT null-terminated) to UTF-8 via
 * WideCharToMultiByte, then emit it JSON-escaped with surrounding quotes.
 * Handles Chinese characters correctly.
 */
static int buf_json_ws(char *b, int pos, int cap,
                       const wchar_t *ws, int wlen, HANDLE heap)
{
    if (wlen <= 0) return buf_app(b, pos, cap, "\"\"");

    int u8sz = KERNEL32$WideCharToMultiByte(
        CP_UTF8, 0, ws, wlen, NULL, 0, NULL, NULL);
    if (u8sz <= 0) return buf_app(b, pos, cap, "\"\"");

    char *u8 = (char *)KERNEL32$HeapAlloc(
        heap, MY_HEAP_ZERO_MEMORY, (SIZE_T)(u8sz + 1));
    if (!u8) return buf_app(b, pos, cap, "\"\"");

    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, ws, wlen, u8, u8sz, NULL, NULL);
    pos = buf_json_u8(b, pos, cap, u8);
    KERNEL32$HeapFree(heap, 0, u8);
    return pos;
}

/*
 * Parse the UTF-16LE pipe-delimited string and emit each "Key": "Value" pair.
 *
 * String format:  |Key:Value|Key:Value|…|\x01\x00\x00
 * The colon split is done on the FIRST colon only, so values containing
 * colons (e.g. "C:\Windows\...") are handled correctly.
 *
 * Caller must have just emitted a ",\n" separator before calling this,
 * and must emit "\n    }" after it returns.
 */
static int emit_pipe_fields(char *b, int pos, int cap,
                             const wchar_t *ws, int wlen, HANDLE heap)
{
    int i = 0, first = 1;

    while (i < wlen && ws[i] != L'\0') {
        /* skip pipe separator */
        if (ws[i] == L'|') i++;
        if (i >= wlen || ws[i] == L'\0') break;

        /* find end of this field */
        int fstart = i;
        while (i < wlen && ws[i] != L'\0' && ws[i] != L'|') i++;
        int fend = i;  /* exclusive */
        if (fend == fstart) continue;

        /* locate the FIRST colon to split key : value */
        int colon = fstart;
        while (colon < fend && ws[colon] != L':') colon++;
        if (colon >= fend) continue;  /* no colon → malformed, skip */

        int klen = colon - fstart;
        int vlen = fend - colon - 1;  /* after the ':' */
        if (klen <= 0) continue;

        if (!first) pos = buf_app(b, pos, cap, ",\n");
        first = 0;

        pos = buf_app(b, pos, cap, "      ");
        pos = buf_json_ws(b, pos, cap, ws + fstart, klen, heap);
        pos = buf_app(b, pos, cap, ": ");
        pos = buf_json_ws(b, pos, cap, ws + colon + 1, vlen, heap);
    }
    return pos;
}

/* ── BOF entry point ─────────────────────────────────────────────────────────── */

void go(char *args, int alen) {
    (void)args; (void)alen;

    HANDLE heap = KERNEL32$GetProcessHeap();

    /* Open E:\galaxy2.dat for reading */
    HANDLE hf = KERNEL32$CreateFileW(
        L"E:\\galaxy2.dat",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hf == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot open E:\\galaxy2.dat");
        return;
    }

    DWORD fsz = KERNEL32$GetFileSize(hf, NULL);
    if (fsz < (DWORD)(FILE_HEADER_SIZE + RECORD_HDR_SIZE) || fsz > 64u * 1024 * 1024) {
        KERNEL32$CloseHandle(hf);
        BeaconPrintf(CALLBACK_ERROR, "[-] Unexpected file size: %u bytes", (unsigned)fsz);
        return;
    }

    BYTE *data = (BYTE *)KERNEL32$HeapAlloc(heap, MY_HEAP_ZERO_MEMORY, (SIZE_T)fsz);
    if (!data) {
        KERNEL32$CloseHandle(hf);
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed for file buffer");
        return;
    }

    DWORD nread = 0;
    if (!KERNEL32$ReadFile(hf, data, fsz, &nread, NULL) || nread < 8) {
        KERNEL32$HeapFree(heap, 0, data);
        KERNEL32$CloseHandle(hf);
        BeaconPrintf(CALLBACK_ERROR, "[-] ReadFile failed");
        return;
    }
    KERNEL32$CloseHandle(hf);

    /* ── Parse file header ── */
    DWORD version   = *(DWORD *)(data + 0);
    DWORD rec_count = *(DWORD *)(data + 4);

    /* Allocate JSON buffer: ~3 KB/record plus a small fixed overhead */
    SIZE_T jcap = (SIZE_T)rec_count * 3072 + 1024;
    char  *jbuf = (char *)KERNEL32$HeapAlloc(heap, MY_HEAP_ZERO_MEMORY, jcap);
    if (!jbuf) {
        KERNEL32$HeapFree(heap, 0, data);
        BeaconPrintf(CALLBACK_ERROR, "[-] HeapAlloc failed for JSON buffer (%u KB)",
                     (unsigned)(jcap / 1024));
        return;
    }

    int p = 0;   /* write cursor */

    /* ── JSON root object ── */
    p = buf_app(jbuf, p, (int)jcap, "{\n");
    p = buf_app(jbuf, p, (int)jcap, "  \"version\": ");
    p = buf_u64 (jbuf, p, (int)jcap, (ULONGLONG)version);
    p = buf_app(jbuf, p, (int)jcap, ",\n");
    p = buf_app(jbuf, p, (int)jcap, "  \"record_count\": ");
    p = buf_u64 (jbuf, p, (int)jcap, (ULONGLONG)rec_count);
    p = buf_app(jbuf, p, (int)jcap, ",\n");
    p = buf_app(jbuf, p, (int)jcap, "  \"records\": [\n");

    /* ── Walk records sequentially using the body_size field ── */
    DWORD off      = FILE_HEADER_SIZE;  /* first record starts at byte 100 */
    int   idx      = 0;
    int   first_r  = 1;

    while ((off + RECORD_HDR_SIZE) <= nread && idx < (int)rec_count) {

        /* body_size = total record bytes − 4 (the size DWORD itself) */
        DWORD body_size = *(DWORD *)(data + off);
        if (body_size < RECORD_META_AFTER_SZ || (off + 4 + body_size) > nread) break;

        /* ── Record metadata fields ── */
        ULONGLONG timestamp = *(ULONGLONG *)(data + off + 0x04);
        DWORD     pid1      = *(DWORD *)    (data + off + 0x1C);
        DWORD     pid2      = *(DWORD *)    (data + off + 0x20);
        DWORD     pid3      = *(DWORD *)    (data + off + 0x24);
        DWORD     record_id = *(DWORD *)    (data + off + 0x28);

        /* ── Wide-character pipe string ── */
        /* string byte length = body_size - RECORD_META_AFTER_SZ */
        DWORD          wbytes = body_size - RECORD_META_AFTER_SZ;
        const wchar_t *ws     = (const wchar_t *)(data + off + RECORD_HDR_SIZE);
        int            wlen   = (int)(wbytes / 2);  /* wchars */

        /* trim trailing null and SOH control characters */
        while (wlen > 0 && (ws[wlen - 1] == L'\0' || ws[wlen - 1] == L'\x01'))
            wlen--;

        /* ── Emit record JSON object ── */
        if (!first_r) p = buf_app(jbuf, p, (int)jcap, ",\n");
        first_r = 0;

        p = buf_app(jbuf, p, (int)jcap, "    {\n");

        p = buf_app(jbuf, p, (int)jcap, "      \"index\": ");
        p = buf_u64(jbuf, p, (int)jcap, (ULONGLONG)idx);

        p = buf_app(jbuf, p, (int)jcap, ",\n      \"timestamp_ticks\": ");
        p = buf_u64(jbuf, p, (int)jcap, timestamp);

        p = buf_app(jbuf, p, (int)jcap, ",\n      \"pid1\": ");
        p = buf_u64(jbuf, p, (int)jcap, (ULONGLONG)pid1);

        p = buf_app(jbuf, p, (int)jcap, ",\n      \"pid2\": ");
        p = buf_u64(jbuf, p, (int)jcap, (ULONGLONG)pid2);

        p = buf_app(jbuf, p, (int)jcap, ",\n      \"pid3\": ");
        p = buf_u64(jbuf, p, (int)jcap, (ULONGLONG)pid3);

        p = buf_app(jbuf, p, (int)jcap, ",\n      \"record_id\": ");
        p = buf_u64(jbuf, p, (int)jcap, (ULONGLONG)record_id);

        /* comma + newline bridge into the pipe fields */
        p = buf_app(jbuf, p, (int)jcap, ",\n");
        p = emit_pipe_fields(jbuf, p, (int)jcap, ws, wlen, heap);

        p = buf_app(jbuf, p, (int)jcap, "\n    }");

        off += 4 + body_size;   /* advance to next record */
        idx++;
    }

    /* ── Close JSON ── */
    p = buf_app(jbuf, p, (int)jcap, "\n  ]\n}\n");

    /* ── Output ── */
    BeaconOutput(CALLBACK_OUTPUT, jbuf, p);

    KERNEL32$HeapFree(heap, 0, jbuf);
    KERNEL32$HeapFree(heap, 0, data);
}
