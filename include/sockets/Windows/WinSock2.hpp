#pragma once

#ifdef __WIN32__

#include "sockets/Windows/Headers.hpp"

#include <stdexcept>
#include <string>

namespace sck
{

/**
 * @struct WinSock2
 * @brief Manages Windows Sockets API (Winsock) initialization and cleanup
 *
 * Implements the Singleton pattern to ensure:
 * - Thread-safe one-time initialization of Winsock 2.2+
 * - Automatic cleanup on program termination
 * - Version requirement enforcement
 *
 * @warning This must be instantiated before any socket operations
 * @note Uses Meyer's Singleton pattern (thread-safe in C++11+)
 */
struct WinSock2
{
    /**
     * @brief Initializes Winsock 2.2+
     * @throw std::runtime_error if:
     * - WSAStartup fails (error code included in message)
     * - Winsock version < 2.0 is detected
     *
     * @post Winsock is initialized and version checked
     */
    WinSock2()
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            throw std::runtime_error("WSAStartup failed with error: " + std::to_string(WSAGetLastError()));
        }
        if (LOBYTE(wsaData.wVersion) < 2)
        {
            WSACleanup();
            throw std::runtime_error(
                "Requires Winsock 2.0+ (found version: " + std::to_string(LOBYTE(wsaData.wVersion)) + "." +
                std::to_string(HIBYTE(wsaData.wVersion)) + ")");
        }
    }

    /**
     * @brief Cleans up Winsock resources
     * @note Marked noexcept to prevent termination during stack unwinding
     * @post All Winsock resources are released
     */
    ~WinSock2() noexcept
    {
        WSACleanup(); // Failure here shouldn't throw
    }

    /**
     * @brief Gets the singleton instance
     * @return WinSock2& Const reference to the single instance
     *
     * Features:
     * - Thread-safe initialization (C++11+)
     * - Lazy initialization (on first use)
     * - Guaranteed destruction
     *
     * @usage `WinSock2::instance();` before socket operations
     */
    static const WinSock2 &instance()
    {
        static const WinSock2 w = WinSock2();
        return w;
    }
};

} // namespace sck

#endif