#ifndef PUZZLE_COMMON_H
#define PUZZLE_COMMON_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

static inline wchar_t *str_to_wide(const char *s)
{
    int len = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    wchar_t *w = (wchar_t *)malloc(len * sizeof(wchar_t));
    if (w) MultiByteToWideChar(CP_ACP, 0, s, -1, w, len);
    return w;
}

static inline char *wide_to_str(const wchar_t *w, int wlen)
{
    if (!w) return NULL;
    int len = WideCharToMultiByte(CP_ACP, 0, w, wlen, NULL, 0, NULL, NULL);
    char *s = (char *)malloc(len + 1);
    if (s) {
        WideCharToMultiByte(CP_ACP, 0, w, wlen, s, len, NULL, NULL);
        s[len] = '\0';
    }
    return s;
}

static inline BYTE *read_file_bytes(const char *path, size_t *out_size)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE) { CloseHandle(h); return NULL; }
    BYTE *buf = (BYTE *)malloc(sz);
    if (!buf) { CloseHandle(h); return NULL; }
    DWORD rd;
    if (!ReadFile(h, buf, sz, &rd, NULL)) { free(buf); CloseHandle(h); return NULL; }
    CloseHandle(h);
    *out_size = (size_t)rd;
    return buf;
}

static inline void xor_crypt(BYTE *data, size_t data_len,
                             const BYTE *key, size_t key_len)
{
    for (size_t i = 0; i < data_len; i++)
        data[i] ^= key[i % key_len];
}

static inline void trim(char *s)
{
    size_t len = strlen(s);
    while (len > 0 && (s[len-1]=='\n' || s[len-1]=='\r' ||
                       s[len-1]==' '  || s[len-1]=='\t'))
        s[--len] = '\0';
}

static inline void prompt(const char *msg, char *buf, size_t sz)
{
    printf("%s", msg);
    fflush(stdout);
    if (fgets(buf, (int)sz, stdin)) trim(buf);
}

#endif
