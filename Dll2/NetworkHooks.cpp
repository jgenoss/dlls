#include "pch.h"
#include "NetworkHooks.h"
#include "TokenGenerator.h"

// Initialize static members
NetworkHooks::SENDTO NetworkHooks::OriginalSendTo = NULL;
NetworkHooks::RECVFROM NetworkHooks::OriginalRecvFrom = NULL;
NetworkHooks::RECV NetworkHooks::OriginalRecv = NULL;
std::string NetworkHooks::m_SecureToken = TokenGenerator::generateSecureToken();
bool NetworkHooks::m_InitialMessageSent = false;
const char* NetworkHooks::DEBUG_LOG_FILE = "network_debug.log";

bool NetworkHooks::Initialize() {
    HMODULE ws2 = GetModuleHandle(L"ws2_32.dll");
    if (!ws2) {
        std::cout << "Error: No se pudo cargar ws2_32.dll" << std::endl;
        return false;
    }

    OriginalSendTo = (SENDTO)GetProcAddress(ws2, "sendto");
    OriginalRecv = (RECV)GetProcAddress(ws2, "recv");
    OriginalRecvFrom = (RECVFROM)GetProcAddress(ws2, "recvfrom");

    if (!OriginalSendTo || !OriginalRecv || !OriginalRecvFrom) {
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

std::string NetworkHooks::GetServerIP() {
    // Obtén el comando original de la línea de comandos del proceso
    char cmdLine[1024];
    std::string serverIP = "";
    char* context = nullptr; // Contexto para strtok_s

    // Verifica si GetCommandLineA devuelve un valor válido
    if (GetCommandLineA()) {
        strcpy_s(cmdLine, GetCommandLineA());

        // Analiza los parámetros de la línea de comandos
        char* token = strtok_s(cmdLine, " ", &context);
        while (token != nullptr) {
            if (strcmp(token, "-server") == 0) {
                // Si encontramos el parámetro -server, obtenemos la IP siguiente
                token = strtok_s(nullptr, " ", &context);  // Obtener el siguiente token (la IP)
                if (token != nullptr) {
                    serverIP = token;  // Guardamos la IP en la variable
                }
            }
            token = strtok_s(nullptr, " ", &context);
        }
    }

    return serverIP;  // Devolvemos la IP como un string
}

int NetworkHooks::GetSocketPort(SOCKET s, bool isRemote) {
    sockaddr_in addr;
    int addrLen = sizeof(addr);

    if (isRemote) {
        getpeername(s, (sockaddr*)&addr, &addrLen); // Puerto remoto (cliente)
    }
    else {
        getsockname(s, (sockaddr*)&addr, &addrLen); // Puerto local (servidor)
    }

    return ntohs(addr.sin_port);
}

std::string NetworkHooks::GetProtocolType(SOCKET s) {
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

void NetworkHooks::WriteToLog(const std::string& message) {
    std::ofstream logFile(DEBUG_LOG_FILE, std::ios::app);
    if (logFile.is_open()) {
        logFile << message << std::endl;
        logFile.close();
    }
}

std::string NetworkHooks::HexDump(const char* data, int length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < length; ++i) {
        ss << std::setw(2) << (unsigned int)(unsigned char)data[i] << " ";
        if ((i + 1) % 16 == 0) ss << "\n";
    }
    return ss.str();
}

void NetworkHooks::DebugPacket(const char* buffer, int length, const std::string& direction) {
    std::stringstream ss;
    ss << "[" << direction << "] (" << length << " bytes) \nHEX: ";

    // Imprimir hexadecimal
    for (int i = 0; i < length; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)buffer[i] << " ";
    }

    ss << "\nASCII: ";
    // Imprimir caracteres ASCII (filtra no imprimibles)
    for (int i = 0; i < length; i++) {
        char c = buffer[i];
        ss << (isprint(c) ? c : '.');
    }

    WriteToLog(ss.str());
}

void NetworkHooks::GetSocketInfo(SOCKET sock) {
    sockaddr_in addr;
    int addrLen = sizeof(addr);

    if (getsockname(sock, (sockaddr*)&addr, &addrLen) == 0) {
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ipStr, sizeof(ipStr));
        int port = ntohs(addr.sin_port);

        std::cout << "Socket vinculado a: " << ipStr << ":" << port << std::endl;
    }
    else {
        std::cerr << "Error en getsockname(): " << WSAGetLastError() << std::endl;
    }
}

int WINAPI NetworkHooks::CustomSendTo(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen) {
    // Solo procesar si es un socket válido y dirección IPv4
    if (s != INVALID_SOCKET) {
        sockaddr_in* addr_in = (sockaddr_in*)to;

        // Enviar mensaje inicial si es la primera vez y es el puerto correcto
        if (!m_InitialMessageSent && ntohs(addr_in->sin_port) == 8701) {
            std::string message = "TOKEN:" + m_SecureToken;
            int result = OriginalSendTo(s, message.c_str(), message.length(), flags, to, tolen);

            if (result != SOCKET_ERROR) {
                m_InitialMessageSent = true;
            }
        }
    }

    return OriginalSendTo(s, buf, len, flags, to, tolen);
}

int WINAPI NetworkHooks::CustomRecvUDP(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    int result = OriginalRecvFrom(s, buf, len, flags, from, fromlen);
    // Additional processing can be added here if needed
    return result;
}

int WINAPI NetworkHooks::CustomRecvTCP(SOCKET s, char* buf, int len, int flags) {
    int result = OriginalRecv(s, buf, len, flags);
    // Additional processing can be added here if needed
    return result;
}