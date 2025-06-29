#pragma once

#include <sockets/Socket.hpp>
#include <sockets/SocketHandle.hpp>

#ifdef __WIN32__

#include "sockets/Windows/Headers.hpp"

#else

#include <arpa/inet.h>
#include <cstddef>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#endif

#include <cstdint>
#include <stdexcept>
#include <string>

namespace sck::impl
{
/**
 * @class SocketImpl
 * @brief Platform-specific socket implementation wrapper
 *
 * This class provides low-level socket operations with platform-independent interface.
 * It handles the differences between Windows and Unix-like systems (Linux, macOS, etc.)
 * for basic socket operations.
 */
class SocketImpl
{
  public:
    /**
     * @typedef AddrLen
     * @brief Type for address length parameter in socket calls
     *
     * On Windows: int
     * On Unix: socklen_t
     */
#ifdef __WIN32__
    using AddrLen = int;
#else
    using AddrLen = socklen_t;
#endif

    /**
     * @brief Creates a sockaddr_in structure for IPv4 addresses
     *
     * @param addr The IPv4 address in host byte order
     * @param port The port number in host byte order
     * @return sockaddr_in Initialized address structure in network byte order
     */
    static sockaddr_in createAddress(const uint32_t addr, const unsigned short port);

    /**
     * @brief Gets the platform-specific invalid socket handle value
     *
     * @return SocketHandle The invalid socket handle value:
     *         => INVALID_SOCKET on Windows
     *         => -1 on Unix-like systems
     */
    static SocketHandle invalidHandle();

    /**
     * @brief Checks if a socket handle is valid
     *
     * @param handle The socket handle to check
     * @return true if the handle is valid
     * @return false if the handle is invalid
     */
    static bool isValidHandle(SocketHandle handle);

    /**
     * @brief Closes a socket handle
     *
     * @param handle The socket handle to close
     *
     * @note On Windows, this calls closesocket()
     * @note On Unix, this calls close()
     */
    static void close(SocketHandle handle);

    /**
     * @brief Sets the blocking mode of a socket
     *
     * @param handle The socket handle to configure
     * @param blocking Whether to set blocking (true) or non-blocking (false) mode
     */
    static void setBlocking(SocketHandle handle, const bool blocking);

    /**
     * @brief Gets the status corresponding to the last socket error
     *
     * @return Socket::Status The status corresponding to the last error:
     *         => Socket::Status::Done on success
     *         => Appropriate error status based on errno (Unix) or WSAGetLastError() (Windows)
     */
    static Socket::Status getErrorStatus();

#ifdef __WIN32__
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
         * @return WinSock2& Reference to the single instance
         *
         * Features:
         * - Thread-safe initialization (C++11+)
         * - Lazy initialization (on first use)
         * - Guaranteed destruction
         *
         * @usage `WinSock2::instance();` before socket operations
         */
        static WinSock2 &instance()
        {
            static WinSock2 w;
            return w;
        }
    };
#endif
};
} // namespace sck::impl