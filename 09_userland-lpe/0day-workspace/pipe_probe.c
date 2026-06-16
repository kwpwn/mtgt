/*
 * pipe_probe.c — Named pipe protocol probe
 * Build: cl /nologo pipe_probe.c /Fe:pipe_probe.exe
 */
#include <windows.h>
#include <stdio.h>

static void probe(const char *pipeName) {
    char fullName[256];
    sprintf_s(fullName, sizeof(fullName), "\\\\.\\pipe\\%s", pipeName);
    printf("=== %s ===\n", fullName);

    HANDLE h = CreateFileA(fullName, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("  ConnectFailed: %u\n", GetLastError());
        return;
    }
    printf("  Connected OK\n");

    /* Set to message mode if possible */
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(h, &mode, NULL, NULL);

    /* Read initial data (server may send something on connect) */
    BYTE buf[4096] = {0};
    DWORD bread = 0;
    BOOL ok = ReadFile(h, buf, sizeof(buf)-1, &bread, NULL);
    DWORD err = GetLastError();

    if (bread > 0) {
        printf("  Received %u bytes on connect:\n  HEX: ", bread);
        for (DWORD i = 0; i < min(bread, 64); i++) printf("%02X ", buf[i]);
        printf("\n  ASCII: ");
        for (DWORD i = 0; i < min(bread, 64); i++) printf("%c", (buf[i] >= 0x20 && buf[i] < 0x7f) ? buf[i] : '.');
        printf("\n");
    } else {
        printf("  No initial data (err=%u)\n", err);
    }

    /* Try sending some probe payloads */
    const char *probes[] = {
        "\x00\x00\x00\x00",           /* 4 null bytes */
        "\x01\x00\x00\x00",           /* length-prefixed 1 */
        "{\"cmd\":\"status\"}",        /* JSON */
        "GET / HTTP/1.0\r\n\r\n",     /* HTTP */
        "\x00",                        /* null */
    };
    int probe_lens[] = { 4, 4, 16, 18, 1 };

    for (int p = 0; p < 5; p++) {
        memset(buf, 0, sizeof(buf));
        DWORD written = 0;
        WriteFile(h, probes[p], probe_lens[p], &written, NULL);

        bread = 0;
        ok = ReadFile(h, buf, sizeof(buf)-1, &bread, NULL);
        err = GetLastError();
        if (bread > 0) {
            printf("  Probe[%d] response: %u bytes | HEX: ", p, bread);
            for (DWORD i = 0; i < min(bread, 48); i++) printf("%02X ", buf[i]);
            printf("\n");
        }
    }

    CloseHandle(h);
    printf("\n");
}

int main(void) {
    const char *pipes[] = {
        "asuscert",
        "AuraPipe1",
        "ArmouryCrateDeviceMonitor",
        "BuildService",
        "IncrediBuild",
        NULL
    };
    for (int i = 0; pipes[i]; i++) probe(pipes[i]);
    return 0;
}
