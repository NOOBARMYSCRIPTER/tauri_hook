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

typedef void(__fastcall* tSub1405EB340)(__int64, __int64, __int64, __int64, __int64);
tSub1405EB340 fpSub1405EB340 = nullptr;

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

__int64 __fastcall detoursSub1403A447E(__int64 a1, __int64* a2, char* a3) {
    Logf("--- Request Construction Detected ---");

    if (a2) {
        unsigned char* raw = (unsigned char*)a2;
        for (int i = 0; i < 512; i++) {
            if (raw[i] == '{' || (raw[i] == 'H' && raw[i+1] == 'o' && raw[i+2] == 's' && raw[i+3] == 't')) {
                Logf("[DATA FOUND AT OFFSET %d] %s", i, &raw[i]);
            }
        }
    }

    if (a3) {
        char* urlPtr = *(char**)(a3 + 104);
        size_t urlLen = *(size_t*)(a3 + 112);
        if (urlPtr && !IsBadReadPtr(urlPtr, urlLen)) {
            Logf("[URL] %.*s", (int)urlLen, urlPtr);
        }
    }

    return fpSub1403A447E(a1, a2, a3);
}

void ScanForData(const char* label, uintptr_t addr, size_t size) {
    if (IsBadReadPtr((void*)addr, size)) return;
    unsigned char* data = (unsigned char*)addr;
    for (size_t i = 0; i < size - 5; i++) {
        if (data[i] == '{' || (data[i] == 'H' && data[i+1] == 'o' && data[i+2] == 's')) {
            Logf("[%s FOUND] %s", label, &data[i]);
        }
    }
}

void __fastcall detoursSub1405EB340(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5) {
    Logf("--- LOG TRIGGERED (sub_1405EB340) ---");

    if (a1 && !IsBadReadPtr((void*)a1, 32)) {
        Logf("[LOG LABEL] %s", (char*)a1);
    }

    if (a3) {
        ScanForData("A3_DIRECT", (uintptr_t)a3, 512);
        
        uintptr_t deeper = *(uintptr_t*)a3;
        if (deeper > 0x10000) {
            ScanForData("A3_DEEP", deeper, 1024);
        }
    }

    if (a5) ScanForData("A5_SCAN", (uintptr_t)a5, 256);


    fpSub1405EB340(a1, a2, a3, a4, a5);
}

DWORD WINAPI InitThread(LPVOID) {
    HMODULE hMinHookDll = LoadMinHookNearModule();
    if (!hMinHookDll) return 0;

    pMH_Initialize = (PFN_MH_Initialize)GetProcAddress(hMinHookDll, "MH_Initialize");
    pMH_CreateHook = (PFN_MH_CreateHook)GetProcAddress(hMinHookDll, "MH_CreateHook");
    pMH_EnableHook = (PFN_MH_EnableHook)GetProcAddress(hMinHookDll, "MH_EnableHook");

    if (pMH_Initialize() == 0) {
        uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
        
        uintptr_t targetLog = base + 0x5EB340;
        uintptr_t targetReq = base + 0x3A447E;

        pMH_CreateHook((LPVOID)targetLog, &detoursSub1405EB340, (LPVOID*)&fpSub1405EB340);
        pMH_EnableHook((LPVOID)targetLog);

        // pMH_CreateHook((LPVOID)targetReq, &detoursSub1403A447E, (LPVOID*)&fpSub1403A447E);
        // pMH_EnableHook((LPVOID)targetReq);

        Logf("[OK] Hooks set. Waiting for requests...");
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) {
    if (r == DLL_PROCESS_ATTACH) CreateThread(0, 0, InitThread, 0, 0, 0);
    return TRUE;
}
