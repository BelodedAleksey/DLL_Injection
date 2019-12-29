#include <windows.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    printf("My PID is %lu (0x%lx)\n", GetCurrentProcessId(), GetCurrentProcessId());
    fflush(stdout);
    MessageBoxW(
            NULL,
            L"Close when ready...",
            L"First message box",
            MB_OK
    );
    char *ex = getenv("HOOK");
    if (ex && strcmp("1", ex) == 0) {
        HMODULE mod = LoadLibraryW(L"detour_test_lib.dll");
        if (!mod) {
            printf("LoadLibraryW failed: error number %lu\n", GetLastError());
            fflush(stdout);
            return 1;
        }
    }
    MessageBoxW(
            NULL,
            L"This is just a regular code sample",
            L"Nothing to see here",
            MB_OK
    );
}
