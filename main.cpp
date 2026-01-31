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

typedef __int64(__fastcall* tSub1403A3DBB)(__int64*, __int64, __int64);
tSub1403A3DBB fpSub1403A3DBB = nullptr;

void Logf(const char* format, ...) {
    char buffer[2048];
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

std::string HexDump(void* ptr, int size) {
    if (!ptr || IsBadReadPtr(ptr, size)) return "[INVALID]";
    unsigned char* p = (unsigned char*)ptr;
    std::stringstream ss;
    for (int i = 0; i < size; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)p[i] << " ";
    }
    return ss.str();
}

__int64 __fastcall detoursSub1403A3DBB(__int64* a1, __int64 a2, __int64 a3) {
    __int64 result = fpSub1403A3DBB(a1, a2, a3);

    static int calls = 0;
    if (++calls % 5 == 0) {
        Logf(">>> sub_1403A3DBB Called (%d). Result: %lld", calls, result);
        
        if (a1) {
            Logf("    a1 Dump: %s", HexDump(a1, 48).c_str());
            
            uintptr_t dataPtr = a1[1];
            if (dataPtr > 0x10000 && !IsBadReadPtr((void*)dataPtr, 64)) {
                Logf("    Data at [a1+8]: %s", HexDump((void*)dataPtr, 64).c_str());
                
                char* s = (char*)dataPtr;
                for (int i = 0; i < 60; i++) {
                    if (s[i] == 'h' && s[i+1] == 't' && s[i+2] == 't') {
                        Logf("    [!] Possible URL: %s", &s[i]);
                        break;
                    }
                }
            }
        }
    }

    return result;
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
    Logf("--- DLL Injected. Initializing... ---");
    
    HMODULE hMinHookDll = LoadMinHookNearModule();
    if (!hMinHookDll) {
        Logf("[ERR] MinHook.x64.dll not found nearby!");
        return 0;
    }

    pMH_Initialize = (PFN_MH_Initialize)GetProcAddress(hMinHookDll, "MH_Initialize");
    pMH_CreateHook = (PFN_MH_CreateHook)GetProcAddress(hMinHookDll, "MH_CreateHook");
    pMH_EnableHook = (PFN_MH_EnableHook)GetProcAddress(hMinHookDll, "MH_EnableHook");

    if (pMH_Initialize && pMH_Initialize() == 0) {
        uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
        uintptr_t target = base + 0x3A3DBB;

        int status = pMH_CreateHook((LPVOID)target, &detoursSub1403A3DBB, (LPVOID*)&fpSub1403A3DBB);
        if (status == 0) {
            pMH_EnableHook((LPVOID)target);
            Logf("[OK] Hook set at 0x%p", target);
        } else {
            Logf("[ERR] MH_CreateHook failed. Status: %d", status);
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
