#include <windows.h>
#include <stdio.h>

static void probe_wait(const char *pipeName, DWORD waitMs) {
    char fullName[256];
    sprintf_s(fullName, sizeof(fullName), "\\\\.\\pipe\\%s", pipeName);
    printf("=== %s (wait %ums) ===\n", fullName, waitMs);
    
    BOOL waited = WaitNamedPipeA(fullName, waitMs);
    if (!waited) { printf("  WaitNamedPipe failed: %u\n", GetLastError()); return; }
    printf("  WaitNamedPipe OK\n");
    
    HANDLE h = CreateFileA(fullName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { printf("  CreateFile failed: %u\n", GetLastError()); return; }
    printf("  Connected!\n");
    
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(h, &mode, NULL, NULL);
    
    BYTE buf[8192] = {0}; DWORD n = 0;
    // Read immediately
    BOOL ok = ReadFile(h, buf, sizeof(buf)-1, &n, NULL);
    if (n > 0) {
        printf("  Initial recv %u bytes | HEX:", n);
        for (DWORD i = 0; i < (n < 64 ? n : 64); i++) printf(" %02X", buf[i]);
        printf("\n");
    }
    
    // Send some test payloads
    BYTE probes[][16] = {
        {0x00,0x00,0x00,0x00},                  /* 4 null dwords */
        {0x01,0x00,0x00,0x00},                  /* cmd=1 */
        {0x02,0x00,0x00,0x00},                  /* cmd=2 */
        {0x00,0x01,0x00,0x00},                  /* different field */
        {0x00,0x00,0x00,0x01},                  /* another */
    };
    int lens[] = {4,4,4,4,4};
    for (int p = 0; p < 5; p++) {
        DWORD w = 0;
        WriteFile(h, probes[p], lens[p], &w, NULL);
        memset(buf, 0, sizeof(buf)); n = 0;
        ReadFile(h, buf, sizeof(buf)-1, &n, NULL);
        if (n > 0) {
            printf("  Probe[%d] -> %u bytes |", p, n);
            for (DWORD i = 0; i < (n < 32 ? n : 32); i++) printf(" %02X", buf[i]);
            printf("\n");
        } else { printf("  Probe[%d] -> no response (err=%u)\n", p, GetLastError()); }
    }
    CloseHandle(h);
    printf("\n");
}

int main(void) {
    probe_wait("asuscert", 30000);  /* wait up to 30s */
    return 0;
}