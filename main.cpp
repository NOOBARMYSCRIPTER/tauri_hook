#include <windows.h>
#include <iostream>
#include <fstream>
#include "MinHook.h"

typedef __int64(__fastcall* tSub1403A447E)(__int64, __int64*, char*);
tSub1403A447E fpSub1403A447E = nullptr;

void LogToFile(const std::string& text) {
    std::ofstream logFile("intercept_log.txt", std::ios_base::app);
    if (logFile.is_open()) {
        logFile << text << std::endl;
        logFile.close();
    }
}

__int64 __fastcall detoursSub1403A447E(__int64 a1, __int64* a2, char* a3) {
    char* urlPtr = *(char**)(a3 + 96);
    size_t urlLen = *(size_t*)(a3 + 104);

    if (urlPtr != nullptr && urlLen > 0 && urlLen < 2048) {
        std::string url(urlPtr, urlLen);
        LogToFile("[HOOK] URL Detected: " + url);
    }

    return fpSub1403A447E(a1, a2, a3);
}

void InitializeHook() {
    if (MH_Initialize() != MH_OK) return;

    uintptr_t baseAddress = (uintptr_t)GetModuleHandleA("app.exe");
    if (!baseAddress) return;

    uintptr_t targetFunc = baseAddress + 0x3A447E;

    if (MH_CreateHook((LPVOID)targetFunc, &detoursSub1403A447E, reinterpret_cast<LPVOID*>(&fpSub1403A447E)) == MH_OK) {
        MH_EnableHook((LPVOID)targetFunc);
        LogToFile("[SYSTEM] Hook initialized successfully at " + std::to_string(targetFunc));
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)InitializeHook, nullptr, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        MH_Uninitialize();
        break;
    }
    return TRUE;
}
