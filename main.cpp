#include <windows.h>
#include <string>
#include <fstream>
#include <vector>

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

void HexDump(const char* label, void* addr, size_t size) {
    unsigned char* p = (unsigned char*)addr;
    std::string dump = "";
    char buf[16];
    for (size_t i = 0; i < size; ++i) {
        sprintf_s(buf, "%02X ", p[i]);
        dump += buf;
        if ((i + 1) % 16 == 0) dump += "| ";
    }
    Logf("%s [Addr: %p]: %s", label, addr, dump.c_str());
}

__int64 __fastcall detoursSub1403A447E(__int64 a1, __int64* a2, char* a3) {
    Logf("[DEBUG] Function sub_1403A447E called!");

    if (a3) {
        for (int offset = 0; offset <= 112; offset += 8) {
            uintptr_t maybePtr = *(uintptr_t*)(a3 + offset);
            size_t maybeLen = *(size_t*)(a3 + offset + 8);

            if (maybeLen > 0 && maybeLen < 1024 && !IsBadReadPtr((void*)maybePtr, maybeLen)) {
                char* strData = (char*)maybePtr;
                
                char preview[17] = {0};
                memcpy(preview, strData, maybeLen > 16 ? 16 : maybeLen);
                
                Logf("[INFO] Offset %d: Ptr=%p, Len=%llu, Data='%s'", offset, (void*)maybePtr, maybeLen, preview);

                if (maybeLen > 4 && strncmp(strData, "http", 4) == 0) {
                    std::string url(strData, maybeLen);
                    Logf("[!!!] FOUND URL at Offset %d: %s", offset, url.c_str());
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
