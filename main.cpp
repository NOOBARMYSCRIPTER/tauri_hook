#include <windows.h>
#include <string>
#include <fstream>
#include <vector>
#include <iomanip>
#include <sstream>

typedef int (WINAPI* PFN_MH_Initialize)();
typedef int (WINAPI* PFN_MH_CreateHook)(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal);
typedef int (WINAPI* PFN_MH_EnableHook)(LPVOID pTarget);

PFN_MH_Initialize   pMH_Initialize = nullptr;
PFN_MH_CreateHook   pMH_CreateHook = nullptr;
PFN_MH_EnableHook   pMH_EnableHook = nullptr;

typedef __int64(__fastcall* tSub14054AC50)(__int64);
tSub14054AC50 fpSub14054AC50 = nullptr;

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

bool SafeRead(void* dest, void* src, size_t size) {
    __try {
        memcpy(dest, src, size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

__int64 __fastcall detoursSub14054AC50(__int64 a1) {
    Logf("--------------------------------------------------");
    Logf(">>> NETWORK REQUEST CAPTURED (Handle: %p)", (void*)a1);

    uintptr_t urlPtr = *(uintptr_t*)(a1 + 2032);
    if (urlPtr > 0x10000) {
        char urlBuf[512] = {0};
        if (SafeRead(urlBuf, (void*)urlPtr, 511)) {
            Logf("[URL] %s", urlBuf);
        }
    }

    uintptr_t uaPtr = *(uintptr_t*)(a1 + 2040);
    if (uaPtr > 0x10000) {
        char uaBuf[256] = {0};
        if (SafeRead(uaBuf, (void*)uaPtr, 255)) {
            Logf("[UA ] %s", uaBuf);
        }
    }

    uintptr_t postPtr = *(uintptr_t*)(a1 + 456);
    if (postPtr > 0x10000) {
        char postBuf[1024] = {0};
        if (SafeRead(postBuf, (void*)postPtr, 1023)) {
            Logf("[BODY] %s", postBuf);
        }
    }

    unsigned char methodIdx = *(unsigned char*)(a1 + 4855);
    Logf("[MET] Method Index: %d", (int)methodIdx);

    Logf("--------------------------------------------------");

    return fpSub14054AC50(a1);
}

static HMODULE LoadMinHookNearModule() {
    char exePath[MAX_PATH] = { 0 };
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

DWORD WINAPI InitThread(LPVOID) {
    Logf("--- Initializing Stealth Network Sniffer ---");
    
    HMODULE hMinHookDll = LoadMinHookNearModule();
    if (!hMinHookDll) return 0;

    pMH_Initialize = (PFN_MH_Initialize)GetProcAddress(hMinHookDll, "MH_Initialize");
    pMH_CreateHook = (PFN_MH_CreateHook)GetProcAddress(hMinHookDll, "MH_CreateHook");
    pMH_EnableHook = (PFN_MH_EnableHook)GetProcAddress(hMinHookDll, "MH_EnableHook");

    if (pMH_Initialize && pMH_Initialize() == 0) {
        uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
        
        uintptr_t target = base + 0x54AC50;

        int status = pMH_CreateHook((LPVOID)target, &detoursSub14054AC50, (LPVOID*)&fpSub14054AC50);
        if (status == 0) {
            pMH_EnableHook((LPVOID)target);
            Logf("[OK] Sniffer active at 0x%p", target);
        } else {
            Logf("[ERR] Hook failed: %d", status);
        }
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) {
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(0, 0, InitThread, 0, 0, 0);
    }
    return TRUE;
}
