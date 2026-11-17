#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        MessageBoxA(NULL, "payload loaded", "sec-blind", MB_OK | MB_TOPMOST);
    }
    return TRUE;
}
