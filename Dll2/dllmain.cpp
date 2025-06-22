#include "pch.h"
#include "Utils.h"
#include "NetworkHooks.h"

NetworkHooks g_NetworkHooks;

typedef void(__fastcall* FUN_005546a0_t)(DWORD param_1);
FUN_005546a0_t FUN_005546a0 = (FUN_005546a0_t)0x005546A0;

const wchar_t Tittle[29] = L"%s%s Online - 1.0 (JGenoss)";

const BYTE port_8701[] = { 0x68, 0xFD, 0x21, 0x00, 0x00 };
const BYTE move_eax_8701[] = { 0xB8, 0xFD, 0x21, 0x00, 0x00 };

//original private key 7BC2763DCEE57FFE0F45F0196F85FE52C2F3E19F
// 
//direccion de memoria key 00ADB29E

//key alberto
const BYTE key1[] = {
    0x04, 0x39, 0x23, 0x78, 0x8A,
    0xE6, 0x62, 0xDA, 0x50, 0xD4,
    0xFB, 0x5F, 0xDA, 0xDB, 0x6D,
    0xDE, 0x83, 0x07, 0x1F, 0x03
};

//key jgenoss
const BYTE key2[] = {
    0xBB, 0x20, 0x5C, 0xBC, 0xF1,
    0x28, 0xB7, 0x2A, 0x2B, 0xB4,
    0x92, 0xB5, 0x55, 0xB3, 0xE1,
    0xE0, 0x0B, 0x42, 0x66, 0x8E
};

// Direcciones exactas del juego
int GetPlayerGrade() {
    // 1. Obtener base del módulo

    HMODULE hModule = GetModuleHandle(NULL);

    if (!hModule) return 0;

    // 2. Navegar el puntero: "Raiderz.exe" + 0x00C33C08 → [base] → +0x450 → valor
    DWORD basePtr = *(DWORD*)((DWORD)hModule + 0x00C33C08);
    if (!basePtr) return 0;

    // 3. Aplicar offset
    DWORD finalAddress = basePtr + 0x450;

    // 4. Leer el valor final
    return *(int*)finalAddress;
}

void CustomFunction() {
    if ((int)GetPlayerGrade() == 3) {
        FUN_005546a0(0x103348c);
        //((void(__fastcall*)(DWORD))0x005546A0)(0x103348c);
    }
}

DWORD WINAPI HookInitThread(LPVOID lpParam) {

    HMODULE hModule = GetModuleHandle(NULL);
    LPVOID baseAddress = (LPVOID)hModule;
    if (hModule != NULL) {
        MODULEINFO modInfo;

        if (GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO))) {
            std::cout << "[DEBUG] Module Information:" << std::endl;
            std::cout << "  Base Address: 0x" << std::hex << modInfo.lpBaseOfDll << std::endl;
			std::cout << "  Entry Point: 0x" << std::hex << modInfo.EntryPoint << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}

extern "C" __declspec(dllexport) void WriteMemory() {
    
    HMODULE hModule = GetModuleHandle(NULL);
    DWORD processId = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess != NULL)
    {
        LPVOID baseAddress = (LPVOID)hModule;

        g_NetworkHooks.Initialize();
        
        Utils::ReplaceBytes((LPVOID)0x00ADB29E, key2, sizeof(key2));
        Utils::ReplaceBytes((LPVOID)0x004D10B7, port_8701);
        Utils::ReplaceBytes((LPVOID)0x0058271B, port_8701);
        Utils::SetByte((LPVOID)0x005973AF, 0xFD);
        Utils::SetByte((LPVOID)0x005973B0, 0x21);
        Utils::ReplaceBytes((LPVOID)0x00612420, move_eax_8701);
        Utils::SetCompleteHook(0xE8, 0x0041BD9B, &CustomFunction);
        Utils::MemorySetUnicode((LPVOID)0x00b00a0c, Tittle);
    }
}

// Punto de entrada de la DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // No hagas trabajo pesado aquí
        //CreateConsole();
        WriteMemory(); // Optimiza el comportamiento
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
