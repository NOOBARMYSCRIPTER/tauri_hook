#include <windows.h>
#include <string>
#include <fstream>
#include <vector>

typedef unsigned __int64 _QWORD;

typedef int (WINAPI* PFN_MH_Initialize)();
typedef int (WINAPI* PFN_MH_CreateHook)(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal);
typedef int (WINAPI* PFN_MH_EnableHook)(LPVOID pTarget);

PFN_MH_Initialize   pMH_Initialize = nullptr;
PFN_MH_CreateHook   pMH_CreateHook = nullptr;
PFN_MH_EnableHook   pMH_EnableHook = nullptr;

typedef __int64(__fastcall* tTauriIPC)(__int64*, __int64, __int64);
tTauriIPC fpTauriIPC = nullptr;

void Logf(const char* format, ...) {
    char buffer[4096];
    va_list args;
    va_start(args, format);
    vsprintf_s(buffer, format, args);
    std::ofstream log("intercept_log.txt", std::ios::app);
    if (log.is_open()) {
        log << buffer << std::endl;
        log.flush();
    }
    va_end(args);
}

void DumpRustString(const char* label, uintptr_t addr) {
    if (addr < 0x10000) return;
    __try {
        char* str = (char*)addr;
        if (str[0] >= 32 && str[0] <= 126) {
            Logf("    [%s]: %hs", label, str);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

__int64 __fastcall detoursTauriIPC(__int64* a1, __int64 a2, __int64 a3) {
    Logf(">>> TAURI IPC CALL DETECTED");

    if (a2) {
        __try {
            uintptr_t dataPtr = *(uintptr_t*)(a2 + 160);
            DumpRustString("IPC DATA", dataPtr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    if (a3) {
        __try {
            uintptr_t cmdPtr = *(uintptr_t*)(a3 + 232);
            DumpRustString("COMMAND/URL", cmdPtr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    return fpTauriIPC(a1, a2, a3);
}

static HMODULE LoadMinHookNearModule() {
    char exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        std::string sExe(exePath);
        size_t posExe = sExe.find_last_of("\\/");
        std::string exeDir = (posExe == std::string::npos) ? "." : sExe.substr(0, posExe);
        std::string dllPath = exeDir + "\\MinHook.x64.dll";
        return LoadLibraryA(dllPath.c_str());
    }
    return nullptr;
}

DWORD WINAPI InitThread(LPVOID) {
    Logf("--- Tauri IPC Sniffer Initializing (Fix Types) ---");
    HMODULE hMinHookDll = LoadMinHookNearModule();
    if (!hMinHookDll) {
        Logf("[ERROR] MinHook.x64.dll not found near EXE");
        return 0;
    }

    pMH_Initialize = (PFN_MH_Initialize)GetProcAddress(hMinHookDll, "MH_Initialize");
    pMH_CreateHook = (PFN_MH_CreateHook)GetProcAddress(hMinHookDll, "MH_CreateHook");
    pMH_EnableHook = (PFN_MH_EnableHook)GetProcAddress(hMinHookDll, "MH_EnableHook");

    if (pMH_Initialize && pMH_Initialize() == 0) {
        uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
        uintptr_t target = base + 0x72B24; 

        if (pMH_CreateHook((LPVOID)target, (LPVOID)detoursTauriIPC, (LPVOID*)&fpTauriIPC) == 0) {
            pMH_EnableHook((LPVOID)target);
            Logf("[OK] Hooked Tauri IPC at 0x%p", (void*)target);
        } else {
            Logf("[ERROR] Failed to create hook");
        }
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) {
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        HANDLE hThread = CreateThread(0, 0, InitThread, 0, 0, 0);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
