// dllmain.cpp : Define el punto de entrada de la aplicación DLL.
#include "pch.h"
#include <wininet.h>
#include <iostream>
#include <vector>
#include "detours.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sstream> 
#include <iomanip>
#include <fstream>
#include <Psapi.h>
#include <thread>
#include <map>
#include <mutex>
#include "TokenGenerator.h"
#include <unordered_map> 

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")

typedef int (WINAPI* RECV)(SOCKET s, char* buf, int len, int flags);
typedef int (WINAPI* RECVFROM)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
typedef int (WINAPI* SENDTO)(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen);
    // Punteros a las funciones originales

SENDTO OriginalSendTo = NULL;
RECVFROM OriginalRecvFrom = NULL;
RECV OriginalRecv = NULL;

// ==================== CONFIGURACIÓN ====================
#define DEBUG_LOG_FILE "network_debug.log"  // Archivo de logs
// =======================================================

int ObtenerPuertoSocket(SOCKET s, bool esRemoto = true) {
    sockaddr_in addr;
    int addrLen = sizeof(addr);

    if (esRemoto) {
        getpeername(s, (sockaddr*)&addr, &addrLen); // Puerto remoto (cliente)
    }
    else {
        getsockname(s, (sockaddr*)&addr, &addrLen); // Puerto local (servidor)
    }

    return ntohs(addr.sin_port);
}

std::string ObtenerTipoProtocolo(SOCKET s) {
    WSAPROTOCOL_INFO protocolInfo;
    int protocolInfoSize = sizeof(protocolInfo);

    if (getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFO, (char*)&protocolInfo, &protocolInfoSize) == 0) {
        if (protocolInfo.iProtocol == IPPROTO_TCP) {
            return "TCP";
        }
        else if (protocolInfo.iProtocol == IPPROTO_UDP) {
            return "UDP";
        }
    }
    return "DESCONOCIDO";
}

std::string HexDump(const char* data, int length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < length; ++i) {
        ss << std::setw(2) << (unsigned int)(unsigned char)data[i] << " ";
        if ((i + 1) % 16 == 0) ss << "\n";
    }
    return ss.str();
}

std::unordered_map<SOCKET, bool> g_validatedSockets;
std::mutex g_socketMutex;

// Función para verificar si un socket está validado
bool IsSocketValidated(SOCKET s) {
    std::lock_guard<std::mutex> lock(g_socketMutex);
    return g_validatedSockets.count(s) && g_validatedSockets[s];
}

// Función para marcar un socket como validado
void MarkSocketAsValidated(SOCKET s) {
    std::lock_guard<std::mutex> lock(g_socketMutex);
    g_validatedSockets[s] = true;
}

// Función para remover un socket (al cerrarse)
void RemoveSocket(SOCKET s) {
    std::lock_guard<std::mutex> lock(g_socketMutex);
    g_validatedSockets.erase(s);
}

int WINAPI CustomSendTo(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen) {

    /*std::stringstream ss;
    ss << "[SENDTO " << ObtenerTipoProtocolo(s) << "] Socket: " << s << ", Length: " << len << "\n";
    ss << "Destino: ";

    if (to->sa_family == AF_INET) {
        sockaddr_in* addr_in = (sockaddr_in*)to;
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr_in->sin_addr), ipStr, INET_ADDRSTRLEN);
        ss << ipStr << ":" << ntohs(addr_in->sin_port) << "\n";
    }
    else {
        ss << "Desconocido\n";
    }

    ss << "Hex:\n" << HexDump(buf, (len > 128) ? 128 : len) << "\n";
    ss << "ASCII: ";
    for (int i = 0; i < len && i < 128; ++i) {
        ss << (isprint(buf[i]) ? buf[i] : '.');
    }

    std::cout << ss.str() << std::endl;*/

    if (ObtenerTipoProtocolo(s) == "UDP" && len == 229) {
        RemoveSocket(s);
    }

    return OriginalSendTo(s, buf, len, flags, to, tolen);
}

int WINAPI CustomRecvUDP(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    // Primero recibimos el paquete
    int result = OriginalRecvFrom(s, buf, len, flags, from, fromlen);

    if (result > 0) {
        // Si el socket ya está validado, retornamos directamente
        if (IsSocketValidated(s)) {
            return result;
        }
        else {
            // Procesamiento del token solo para sockets no validados
            std::string packetData(buf, result);
            std::string tokenPrefix = "TOKEN:";
            size_t tokenPos = packetData.find(tokenPrefix);

            if (tokenPos != std::string::npos) {
                std::string token = packetData.substr(tokenPos + tokenPrefix.length());
                token.erase(std::remove_if(token.begin(), token.end(),
                    [](char c) { return !isprint(c); }), token.end());

                if (TokenGenerator::validateToken(token)) {
                    MarkSocketAsValidated(s);
                    std::cout << "[AUTH] Socket " << std::hex << s << " validado correctamente\n";
                    return result; // Retornamos el paquete recibido
                }
            }
            else {
                std::cerr << "[AUTH ERROR] Socket " << std::hex << s << " no proporcionó token válido\n";
                closesocket(s);
            }
        }
    }

    return result; // Retornamos errores o casos especiales (result <= 0)
}

int WINAPI CustomRecvTCP(SOCKET s, char* buf, int len, int flags) {
    // Recibe los datos usando la función original
    int result = OriginalRecv(s, buf, len, flags);
    int puerto = ObtenerPuertoSocket(s, true);

    return result;
}

// Inicialización de hooks
bool InitializeHooks() {
    HMODULE ws2 = GetModuleHandle(L"ws2_32.dll");
    if (!ws2) {
        std::cout << "Error: No se pudo cargar ws2_32.dll" << std::endl;
        return false;
    }

    OriginalSendTo = (SENDTO)GetProcAddress(ws2, "sendto");
    OriginalRecv = (RECV)GetProcAddress(ws2, "recv");
    OriginalRecvFrom = (RECVFROM)GetProcAddress(ws2, "recvfrom");

    if (!OriginalSendTo || !OriginalRecv || !OriginalRecvFrom ) {
        std::cout << "Error: No se encontraron las funciones originales" << std::endl;
        return false;
    }

    // Aplicar los hooks con Detours
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)OriginalSendTo, CustomSendTo);
    DetourAttach(&(PVOID&)OriginalRecv, CustomRecvTCP);
    DetourAttach(&(PVOID&)OriginalRecvFrom, CustomRecvUDP);
    if (DetourTransactionCommit() != NO_ERROR) {
        std::cout << "Error: Fallo al aplicar los hooks" << std::endl;
        return false;
    }
    return true;
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
        std::this_thread::sleep_for(std::chrono::seconds(3));

        if (!InitializeHooks()) {
            std::cout << "Error: Fallo en la inicializacion hook" << std::endl;
        }
    }

    return 0;
}

extern "C" __declspec(dllexport) void Init() {

    HMODULE hModule = GetModuleHandle(NULL);
    DWORD processId = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess != NULL)
    {
        LPVOID baseAddress = (LPVOID)hModule;

		CreateThread(NULL, 0, HookInitThread, NULL, 0, NULL);
    }
}

// Punto de entrada de la DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Init(); // Optimiza el comportamiento
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

