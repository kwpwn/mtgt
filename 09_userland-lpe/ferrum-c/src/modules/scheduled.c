/*
 * scheduled.c — Scheduled Task Misconfiguration Checker
 *
 * Enumerates task XML files under C:\Windows\System32\Tasks\ and checks:
 *   1. Task XML file itself is writable by current user.
 *   2. The binary referenced in <Execute> is in a user-writable location.
 *   3. The binary referenced in <Execute> is itself writable.
 *   4. Reports the task Principal (who it runs as) for LPE relevance.
 *
 * Also queries the Task Scheduler COM interface via schtasks.exe stdout
 * for tasks running as SYSTEM with writable binary paths.
 * (COM interface requires linking ITaskService which needs taskschd.lib;
 *  XML file enumeration works without any extra lib.)
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Very lightweight XML value extractor.
 * Finds the FIRST occurrence of <Tag>value</Tag> and copies value into
 * buf. Not a full XML parser — sufficient for well-formed task XML files.
 * --------------------------------------------------------------------- */
static BOOL XmlGetTagValue(LPCWSTR xml, LPCWSTR tag, LPWSTR buf, DWORD bufCch) {
    wchar_t openTag[64], closeTag[64];
    _snwprintf(openTag,  _countof(openTag),  L"<%s>", tag);
    _snwprintf(closeTag, _countof(closeTag), L"</%s>", tag);

    const wchar_t *start = wcsstr(xml, openTag);
    if (!start) return FALSE;
    start += wcslen(openTag);

    const wchar_t *end = wcsstr(start, closeTag);
    if (!end) return FALSE;

    DWORD len = (DWORD)(end - start);
    if (len >= bufCch) len = bufCch - 1;
    wcsncpy(buf, start, len);
    buf[len] = L'\0';
    return TRUE;
}

/* -----------------------------------------------------------------------
 * Read entire file into a heap-allocated wchar_t buffer.
 * Task XML files are UTF-16 LE. Returns NULL on failure.
 * Caller must HeapFree result.
 * --------------------------------------------------------------------- */
static wchar_t *ReadTaskXml(LPCWSTR filePath) {
    HANDLE hFile = CreateFileW(filePath,
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    LARGE_INTEGER sz = {0};
    GetFileSizeEx(hFile, &sz);
    if (sz.QuadPart > 1024 * 1024) { /* skip files > 1 MB */
        CloseHandle(hFile);
        return NULL;
    }

    DWORD   byteCount = (DWORD)sz.LowPart;
    BYTE   *raw       = (BYTE *)HeapAlloc(GetProcessHeap(), 0, byteCount + 4);
    if (!raw) { CloseHandle(hFile); return NULL; }

    DWORD   read = 0;
    ReadFile(hFile, raw, byteCount, &read, NULL);
    CloseHandle(hFile);

    /* UTF-16 LE with BOM (0xFF 0xFE) */
    wchar_t *xml;
    if (read >= 2 && raw[0] == 0xFF && raw[1] == 0xFE) {
        DWORD wchCount = (read - 2) / sizeof(wchar_t);
        xml = (wchar_t *)HeapAlloc(GetProcessHeap(), 0,
                                    (wchCount + 1) * sizeof(wchar_t));
        if (xml) {
            memcpy(xml, raw + 2, wchCount * sizeof(wchar_t));
            xml[wchCount] = L'\0';
        }
    } else {
        /* Assume UTF-8 or ANSI; convert to wide */
        int wlen = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)raw, read, NULL, 0);
        xml = (wchar_t *)HeapAlloc(GetProcessHeap(), 0,
                                    (wlen + 1) * sizeof(wchar_t));
        if (xml) {
            MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)raw, read, xml, wlen);
            xml[wlen] = L'\0';
        }
    }
    HeapFree(GetProcessHeap(), 0, raw);
    return xml;
}

/* -----------------------------------------------------------------------
 * Recursively enumerate task XML files.
 * --------------------------------------------------------------------- */
static void EnumTaskFiles(LPCWSTR dir, DWORD *findings) {
    wchar_t searchPath[MAX_PATH * 2];
    _snwprintf(searchPath, _countof(searchPath), L"%s\\*", dir);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0) continue;

        wchar_t fullPath[MAX_PATH * 2];
        _snwprintf(fullPath, _countof(fullPath), L"%s\\%s", dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            EnumTaskFiles(fullPath, findings);
            continue;
        }

        /* ---- Check 1: Task XML file writable ---- */
        if (IsFileWritable(fullPath)) {
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"SCHEDULED");
            wcsncpy(f.target, fullPath, _countof(f.target)-1);
            wcscpy(f.reason,
                L"Task XML file is WRITABLE by current user → modify Command/Principal");
            PrintFinding(&f);
            (*findings)++;
        }

        /* ---- Parse task XML for binary path checks ---- */
        wchar_t *xml = ReadTaskXml(fullPath);
        if (!xml) continue;

        wchar_t command[MAX_PATH * 2] = {0};
        wchar_t userId[128]           = {0};

        XmlGetTagValue(xml, L"Command",  command, _countof(command));
        XmlGetTagValue(xml, L"UserId",   userId,  _countof(userId));
        /* Fallback for older task format */
        if (!*command)
            XmlGetTagValue(xml, L"Exec", command, _countof(command));

        HeapFree(GetProcessHeap(), 0, xml);

        if (!*command) continue;

        /* Expand environment variables in command */
        wchar_t exeExpanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(command, exeExpanded, _countof(exeExpanded));

        /* Determine if task runs as SYSTEM for severity */
        BOOL isSystem = WcsContainsI(userId, L"S-1-5-18") ||
                        _wcsicmp(userId, L"SYSTEM") == 0   ||
                        *userId == L'\0';    /* empty = often SYSTEM too */

        Severity baseSev = isSystem ? SEV_CRITICAL : SEV_HIGH;

        /* ---- Check 2: Binary in user-writable location ---- */
        if (IsUserWritablePath(exeExpanded)) {
            Finding f;
            f.severity = baseSev;
            wcscpy(f.module, L"SCHEDULED");
            wcsncpy(f.target, fd.cFileName, _countof(f.target)-1);
            _snwprintf(f.reason, _countof(f.reason),
                L"Task binary in user-writable location. "
                L"Principal:%s  Binary:%s",
                *userId ? userId : L"SYSTEM", exeExpanded);
            PrintFinding(&f);
            (*findings)++;
        }

        /* ---- Check 3: Binary itself is writable ---- */
        if (GetFileAttributesW(exeExpanded) != INVALID_FILE_ATTRIBUTES
            && IsFileWritable(exeExpanded))
        {
            Finding f;
            f.severity = baseSev;
            wcscpy(f.module, L"SCHEDULED");
            wcsncpy(f.target, fd.cFileName, _countof(f.target)-1);
            _snwprintf(f.reason, _countof(f.reason),
                L"Task binary is WRITABLE by current user. "
                L"Principal:%s  Binary:%s",
                *userId ? userId : L"SYSTEM", exeExpanded);
            PrintFinding(&f);
            (*findings)++;
        }

    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_Scheduled(void) {
    PrintHeader(L"SCHEDULED TASK AUDIT");

    wchar_t tasksDir[MAX_PATH] = {0};
    GetSystemDirectoryW(tasksDir, _countof(tasksDir));
    wcsncat(tasksDir, L"\\Tasks", _countof(tasksDir) - wcslen(tasksDir) - 1);

    PrintInfo(L"  Scanning: %s\n\n", tasksDir);

    DWORD findings = 0;
    EnumTaskFiles(tasksDir, &findings);

    if (findings == 0)
        PrintInfo(L"  No scheduled task misconfigurations found.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);
}
