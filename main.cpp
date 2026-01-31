#include <windows.h>
#include <string>
#include <fstream>
#include <vector>
#include <codecvt>
#include <locale>

typedef int (WINAPI *PFN_MH_Initialize)();
typedef int (WINAPI *PFN_MH_Uninitialize)();
typedef int (WINAPI *PFN_MH_CreateHook)(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal);
typedef int (WINAPI *PFN_MH_EnableHook)(LPVOID pTarget);

PFN_MH_Initialize   pMH_Initialize = nullptr;
PFN_MH_Uninitialize pMH_Uninitialize = nullptr;
PFN_MH_CreateHook   pMH_CreateHook = nullptr;
PFN_MH_EnableHook   pMH_EnableHook = nullptr;

typedef __int64(__fastcall* tSub1403A447E)(__int64, __int64*, char*);
tSub1403A447E fpSub1403A447E = nullptr;

void Logf(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsprintf_s(buffer, format, args);
    std::ofstream log("intercept_log.txt", std::ios::app);
    log << buffer << std::endl;
    va_end(args);
}

static HMODULE LoadMinHookNearModule() {
    char exePath[MAX_PATH] = {0};
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        std::string sExe(exePath);
        size_t posExe = sExe.find_last_of("\\/");
        std::string exeDir = (posExe == std::string::npos) ? "." : sExe.substr(0, posExe);
        std::string dllPath = exeDir + "\\MinHook.x64.dll";
        HMODULE h = LoadLibraryA(dllPath.c_str());
        if (h) return h;
    }
    return LoadLibraryA("MinHook.x64.dll");
}

void DumpMemoryStrings(const char* label, uintptr_t startAddr, size_t range) {
    if (IsBadReadPtr((void*)startAddr, range)) return;

    for (size_t i = 0; i < range - 8; i += 1) {
        const char* potentialStr = (const char*)(startAddr + i);
        
        bool looksLikeJson = (potentialStr[0] == '{' && potentialStr[1] == '"');
        bool looksLikeHeader = (strnicmp(potentialStr, "user-agent", 10) == 0 || 
                               strnicmp(potentialStr, "content-type", 12) == 0 ||
                               strnicmp(potentialStr, "authorization", 13) == 0 ||
                               strnicmp(potentialStr, "x-", 2) == 0);

        if (looksLikeJson || looksLikeHeader) {
            Logf("[%s] Found at offset +%llu: %s", label, i, potentialStr);
        }
    }
}

__int64 __fastcall detoursSub1403A447E(__int64 a1, __int64* a2, char* a3) {
    Logf("--- Hook Triggered (Deep Scan) ---");

    if (a3) {
        char* urlPtr = *(char**)(a3 + 104);
        if (!IsBadReadPtr(urlPtr, 1)) Logf("[URL] %s", urlPtr);
        
        DumpMemoryStrings("A3_SCAN", (uintptr_t)a3, 512);
    }

    if (a2) {
        DumpMemoryStrings("A2_SCAN", (uintptr_t)a2, 512);
        
        for (int j = 0; j < 32; j++) {
            uintptr_t ptr = (uintptr_t)a2[j];
            if (ptr > 0x10000 && !IsBadReadPtr((void*)ptr, 64)) {
                DumpMemoryStrings("A2_INDIR_SCAN", ptr, 256);
            }
        }
    }

    return fpSub1403A447E(a1, a2, a3);
}

DWORD WINAPI InitThread(LPVOID) {
    HMODULE hMinHookDll = LoadMinHookNearModule();
    if (!hMinHookDll) {
        Logf("[ERR] MinHook.x64.dll not found!");
        return 0;
    }

    pMH_Initialize = (PFN_MH_Initialize)GetProcAddress(hMinHookDll, "MH_Initialize");
    pMH_CreateHook = (PFN_MH_CreateHook)GetProcAddress(hMinHookDll, "MH_CreateHook");
    pMH_EnableHook = (PFN_MH_EnableHook)GetProcAddress(hMinHookDll, "MH_EnableHook");

    if (pMH_Initialize() == 0) {
        uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
        uintptr_t target = base + 0x3A447E;

        if (pMH_CreateHook((LPVOID)target, &detoursSub1403A447E, (LPVOID*)&fpSub1403A447E) == 0) {
            pMH_EnableHook((LPVOID)target);
            Logf("[OK] Hook set at: %p", target);
        }
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) {
    if (r == DLL_PROCESS_ATTACH) CreateThread(0, 0, InitThread, 0, 0, 0);
    return TRUE;
}
