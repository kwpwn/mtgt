/*
 * test_runner.c – standalone harness, same parse logic as the BOF
 * Output goes to stdout so we can see/redirect the JSON.
 * Compile:
 *   gcc -o test_runner.exe test_runner.c -municode -Wall
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_HEADER_SIZE     100u
#define RECORD_HDR_SIZE      45u
#define RECORD_META_AFTER_SZ 41u

/* ── Buffer helpers ──────────────────────────────────────────────────────── */

static int buf_app(char *b, int pos, int cap, const char *s) {
    while (*s && pos < cap - 1) b[pos++] = *s++;
    return pos;
}
static int buf_appn(char *b, int pos, int cap, const char *s, int n) {
    while (n-- > 0 && pos < cap - 1) b[pos++] = *s++;
    return pos;
}
static int buf_u64(char *b, int pos, int cap, unsigned long long v) {
    char tmp[22]; int n = 0;
    if (v == 0) { tmp[n++] = '0'; }
    else { while (v) { tmp[n++] = (char)('0' + (int)(v % 10)); v /= 10; } }
    for (int i = 0, j = n-1; i < j; i++, j--) { char t=tmp[i]; tmp[i]=tmp[j]; tmp[j]=t; }
    return buf_appn(b, pos, cap, tmp, n);
}
static int buf_json_u8(char *b, int pos, int cap, const char *s) {
    pos = buf_app(b, pos, cap, "\"");
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if      (c == '"')  pos = buf_app(b, pos, cap, "\\\"");
        else if (c == '\\') pos = buf_app(b, pos, cap, "\\\\");
        else if (c == '\n') pos = buf_app(b, pos, cap, "\\n");
        else if (c == '\r') pos = buf_app(b, pos, cap, "\\r");
        else if (c == '\t') pos = buf_app(b, pos, cap, "\\t");
        else if (c < 0x20) {
            const char *hx = "0123456789abcdef";
            char esc[7];
            esc[0]='\\'; esc[1]='u'; esc[2]='0'; esc[3]='0';
            esc[4]=hx[(c>>4)&0xF]; esc[5]=hx[c&0xF]; esc[6]='\0';
            pos = buf_app(b, pos, cap, esc);
        } else { if (pos < cap-1) b[pos++] = (char)c; }
    }
    pos = buf_app(b, pos, cap, "\"");
    return pos;
}
static int buf_json_ws(char *b, int pos, int cap,
                       const wchar_t *ws, int wlen)
{
    if (wlen <= 0) return buf_app(b, pos, cap, "\"\"");
    int u8sz = WideCharToMultiByte(CP_UTF8, 0, ws, wlen, NULL, 0, NULL, NULL);
    if (u8sz <= 0) return buf_app(b, pos, cap, "\"\"");
    char *u8 = (char *)calloc((size_t)(u8sz + 1), 1);
    if (!u8) return buf_app(b, pos, cap, "\"\"");
    WideCharToMultiByte(CP_UTF8, 0, ws, wlen, u8, u8sz, NULL, NULL);
    pos = buf_json_u8(b, pos, cap, u8);
    free(u8);
    return pos;
}
static int emit_pipe_fields(char *b, int pos, int cap,
                             const wchar_t *ws, int wlen)
{
    int i = 0, first = 1;
    while (i < wlen && ws[i] != L'\0') {
        if (ws[i] == L'|') i++;
        if (i >= wlen || ws[i] == L'\0') break;
        int fstart = i;
        while (i < wlen && ws[i] != L'\0' && ws[i] != L'|') i++;
        int fend = i;
        if (fend == fstart) continue;
        int colon = fstart;
        while (colon < fend && ws[colon] != L':') colon++;
        if (colon >= fend) continue;
        int klen = colon - fstart;
        int vlen = fend - colon - 1;
        if (klen <= 0) continue;
        if (!first) pos = buf_app(b, pos, cap, ",\n");
        first = 0;
        pos = buf_app(b, pos, cap, "      ");
        pos = buf_json_ws(b, pos, cap, ws + fstart, klen);
        pos = buf_app(b, pos, cap, ": ");
        pos = buf_json_ws(b, pos, cap, ws + colon + 1, vlen);
    }
    return pos;
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(void) {
    /* Set stdout to UTF-8 so Chinese renders correctly in terminal */
    SetConsoleOutputCP(CP_UTF8);

    FILE *f = _wfopen(L"E:\\galaxy2.dat", L"rb");
    if (!f) { fprintf(stderr, "[-] Cannot open E:\\galaxy2.dat\n"); return 1; }

    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    rewind(f);
    if (fsz < (long)(FILE_HEADER_SIZE + RECORD_HDR_SIZE) || fsz > 64*1024*1024) {
        fprintf(stderr, "[-] Bad file size: %ld\n", fsz);
        fclose(f);
        return 1;
    }

    unsigned char *data = (unsigned char *)malloc((size_t)fsz);
    if (!data) { fclose(f); return 1; }
    if ((long)fread(data, 1, (size_t)fsz, f) != fsz) {
        fprintf(stderr, "[-] Read error\n"); free(data); fclose(f); return 1;
    }
    fclose(f);

    unsigned int version   = *(unsigned int *)(data + 0);
    unsigned int rec_count = *(unsigned int *)(data + 4);

    int jcap = (int)rec_count * 3072 + 1024;
    char *jbuf = (char *)calloc((size_t)jcap, 1);
    if (!jbuf) { free(data); return 1; }

    int p = 0;
    p = buf_app(jbuf, p, jcap, "{\n");
    p = buf_app(jbuf, p, jcap, "  \"version\": ");
    p = buf_u64 (jbuf, p, jcap, version);
    p = buf_app(jbuf, p, jcap, ",\n  \"record_count\": ");
    p = buf_u64 (jbuf, p, jcap, rec_count);
    p = buf_app(jbuf, p, jcap, ",\n  \"records\": [\n");

    unsigned int off = FILE_HEADER_SIZE;
    int idx = 0, first_r = 1;

    while ((off + RECORD_HDR_SIZE) <= (unsigned int)fsz && idx < (int)rec_count) {
        unsigned int body_size = *(unsigned int *)(data + off);
        if (body_size < RECORD_META_AFTER_SZ || (off + 4 + body_size) > (unsigned int)fsz) break;

        unsigned long long timestamp = *(unsigned long long *)(data + off + 0x04);
        unsigned int pid1      = *(unsigned int *)(data + off + 0x1C);
        unsigned int pid2      = *(unsigned int *)(data + off + 0x20);
        unsigned int pid3      = *(unsigned int *)(data + off + 0x24);
        unsigned int record_id = *(unsigned int *)(data + off + 0x28);

        unsigned int    wbytes = body_size - RECORD_META_AFTER_SZ;
        const wchar_t  *ws     = (const wchar_t *)(data + off + RECORD_HDR_SIZE);
        int             wlen   = (int)(wbytes / 2);

        while (wlen > 0 && (ws[wlen-1] == L'\0' || ws[wlen-1] == L'\x01')) wlen--;

        if (!first_r) p = buf_app(jbuf, p, jcap, ",\n");
        first_r = 0;

        p = buf_app(jbuf, p, jcap, "    {\n");
        p = buf_app(jbuf, p, jcap, "      \"index\": ");          p = buf_u64(jbuf, p, jcap, (unsigned long long)idx);
        p = buf_app(jbuf, p, jcap, ",\n      \"timestamp_ticks\": "); p = buf_u64(jbuf, p, jcap, timestamp);
        p = buf_app(jbuf, p, jcap, ",\n      \"pid1\": ");         p = buf_u64(jbuf, p, jcap, pid1);
        p = buf_app(jbuf, p, jcap, ",\n      \"pid2\": ");         p = buf_u64(jbuf, p, jcap, pid2);
        p = buf_app(jbuf, p, jcap, ",\n      \"pid3\": ");         p = buf_u64(jbuf, p, jcap, pid3);
        p = buf_app(jbuf, p, jcap, ",\n      \"record_id\": ");    p = buf_u64(jbuf, p, jcap, record_id);
        p = buf_app(jbuf, p, jcap, ",\n");
        p = emit_pipe_fields(jbuf, p, jcap, ws, wlen);
        p = buf_app(jbuf, p, jcap, "\n    }");

        off += 4 + body_size;
        idx++;
    }

    p = buf_app(jbuf, p, jcap, "\n  ]\n}\n");

    /* Write to stdout as raw bytes (UTF-8) */
    fwrite(jbuf, 1, (size_t)p, stdout);

    free(jbuf);
    free(data);
    return 0;
}
