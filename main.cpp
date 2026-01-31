#include <windows.h>
#include <string>
#include <fstream>

typedef int (WINAPI* PFN_MH_Initialize)();
typedef int (WINAPI* PFN_MH_CreateHook)(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal);
typedef int (WINAPI* PFN_MH_EnableHook)(LPVOID pTarget);

PFN_MH_Initialize   pMH_Initialize = nullptr;
PFN_MH_CreateHook   pMH_CreateHook = nullptr;
PFN_MH_EnableHook   pMH_EnableHook = nullptr;

typedef __int64(__fastcall* tSub14055DF30)(__int64, char*);
tSub14055DF30 fpSub14055DF30 = nullptr;

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

bool SafeReadStr(uintptr_t addr, char* outBuf, size_t maxLen) {
    if (addr < 0x10000) return false;
    __try {
        const char* s = (const char*)addr;
        size_t len = 0;
        while (len < maxLen - 1 && s[len] != '\0') {
            outBuf[len] = s[len];
            len++;
        }
        outBuf[len] = '\0';
        return len > 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

__int64 __fastcall detoursSub14055DF30(__int64 a1, char* a2) {
    Logf(">>> HTTP BUILDER TRIGGERED (Handle: %p)", (void*)a1);

    uintptr_t urlAddr = *(uintptr_t*)(a1 + 4440);
    char urlBuf[1024] = {0};
    if (SafeReadStr(urlAddr, urlBuf, 1024)) {
        Logf("    [URL] %s", urlBuf);
    }

    uintptr_t queryAddr = *(uintptr_t*)(a1 + 4448);
    char queryBuf[1024] = {0};
    if (SafeReadStr(queryAddr, queryBuf, 1024)) {
        Logf("    [QUERY] ?%s", queryBuf);
    }

    unsigned char v8 = *(unsigned char*)(a1 + 4855);
    const char* method = "UNKNOWN";
    switch(v8) {
        case 1: case 2: case 3: method = "POST"; break;
        case 4: method = "PUT"; break;
        case 5: method = "HEAD"; break;
        default: method = "GET"; break;
    }
    Logf("    [METHOD] %s (Internal ID: %d)", method, v8);

    uintptr_t postDataAddr = *(uintptr_t*)(a1 + 456);
    char postBuf[2048] = {0};
    if (SafeReadStr(postDataAddr, postBuf, 2048)) {
        Logf("    [POST BODY] %s", postBuf);
    }

    uintptr_t uaAddr = *(uintptr_t*)(a1 + 2040);
    char uaBuf[256] = {0};
    if (SafeReadStr(uaAddr, uaBuf, 256)) {
        Logf("    [USER-AGENT] %s", uaBuf);
    }

    return fpSub14055DF30(a1, a2);
}

static HMODULE LoadMinHookNearModule() {
    char exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        std::string sExe(exePath);
        size_t posExe = sExe.find_last_of("\\/");
        std::string exeDir = (posExe == std::string::npos) ? "." : sExe.substr(0, posExe);
        HMODULE h = LoadLibraryA((exeDir + "\\MinHook.x64.dll").c_str());
        if (h) return h;
    }
    return LoadLibraryA("MinHook.x64.dll");
}

DWORD WINAPI InitThread(LPVOID) {
    Logf("--- New Sniffer Initializing (sub_14055DF30) ---");
    HMODULE hMinHookDll = LoadMinHookNearModule();
    if (!hMinHookDll) return 0;

    pMH_Initialize = (PFN_MH_Initialize)GetProcAddress(hMinHookDll, "MH_Initialize");
    pMH_CreateHook = (PFN_MH_CreateHook)GetProcAddress(hMinHookDll, "MH_CreateHook");
    pMH_EnableHook = (PFN_MH_EnableHook)GetProcAddress(hMinHookDll, "MH_EnableHook");

    if (pMH_Initialize && pMH_Initialize() == 0) {
        uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
        uintptr_t target = base + 0x55DF30;

        if (pMH_CreateHook((LPVOID)target, &detoursSub14055DF30, (LPVOID*)&fpSub14055DF30) == 0) {
            pMH_EnableHook((LPVOID)target);
            Logf("[OK] Hooked HTTP Builder at 0x%p", target);
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
