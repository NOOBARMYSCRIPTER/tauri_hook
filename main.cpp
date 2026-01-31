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

void TryLogData(const char* label, int offset, uintptr_t ptr, size_t len) {
    if (len == 0 || len > 2048 || IsBadReadPtr((void*)ptr, len)) return;

    std::string ascii((char*)ptr, len);
    bool isAscii = true;
    for (char c : ascii) {
        if (c != 0 && (c < 32 || c > 126)) { isAscii = false; break; }
    }

    if (isAscii && ascii.length() > 0) {
        Logf("[%s] Offset %d: (ASCII) '%s'", label, offset, ascii.c_str());
    } 
    else {
        try {
            std::wstring wstr((wchar_t*)ptr, len / 2);
            if (wstr.length() > 0) {
                Logf("[%s] Offset %d: (UTF16) '%ls'", label, offset, wstr.c_str());
            }
        } catch (...) {}
    }
}

__int64 __fastcall detoursSub1403A447E(__int64 a1, __int64* a2, char* a3) {
    if (a3) {
        char* urlPtr = *(char**)(a3 + 104);
        size_t urlLen = *(size_t*)(a3 + 112);

        if (urlPtr && !IsBadReadPtr(urlPtr, urlLen)) {
            Logf("[URL] %.*s", (int)urlLen, urlPtr);
        }
    }

    if (a2) {
        for (int i = 0; i < 30; i++) {
            char* maybeData = (char*)a2[i];
            size_t maybeLen = (size_t)a2[i+1];

            if (maybeLen > 2 && maybeLen < 5000 && !IsBadReadPtr(maybeData, maybeLen)) {
                if (maybeData[0] == '{' || strncmp(maybeData, "ey", 2) == 0) {
                    Logf("[BODY/DATA] Offset %d, Len %llu: %.*s", i * 8, maybeLen, (int)maybeLen, maybeData);
                }
                if (maybeLen >= 3 && maybeLen <= 7) {
                    if (strcmp(maybeData, "POST") == 0 || strcmp(maybeData, "GET") == 0) {
                        Logf("[METHOD] %s", maybeData);
                    }
                }
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
