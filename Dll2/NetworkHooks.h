#pragma once
#include <map>
#include "detours.h"

class NetworkHooks {
public:
    // Initialize and cleanup
    static bool Initialize();

    // Socket connection utilities
    static std::string GetServerIP();
    static int GetSocketPort(SOCKET s, bool isRemote = true);
    static std::string GetProtocolType(SOCKET s);

    // Debug and logging
    static void WriteToLog(const std::string& message);
    static std::string HexDump(const char* data, int length);
    static void DebugPacket(const char* buffer, int length, const std::string& direction);
    static void GetSocketInfo(SOCKET sock);

private:
    // Function pointer typedefs for original Winsock functions
    typedef int (WINAPI* RECV)(SOCKET s, char* buf, int len, int flags);
    typedef int (WINAPI* RECVFROM)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
    typedef int (WINAPI* SENDTO)(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen);

    // Pointers to original functions
    static SENDTO OriginalSendTo;
    static RECVFROM OriginalRecvFrom;
    static RECV OriginalRecv;

    // Custom hook functions
    static int WINAPI CustomSendTo(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen);
    static int WINAPI CustomRecvUDP(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
    static int WINAPI CustomRecvTCP(SOCKET s, char* buf, int len, int flags);

    // Token management
    static std::string m_SecureToken;
    static bool m_InitialMessageSent;

    // Constants
    static const char* DEBUG_LOG_FILE;
};