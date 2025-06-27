#pragma once

#include <sockets/Socket.hpp>
#include <sockets/SocketHandle.hpp>

#ifdef __WIN32__

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

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
    using Size = int;
#else
    using AddrLen = socklen_t;
    using Size = size_t;
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
     *         - INVALID_SOCKET on Windows
     *         - -1 on Unix-like systems
     */
    static SocketHandle invalidSocketHandle();

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
     *         - Socket::Status::Done on success
     *         - Appropriate error status based on errno (Unix) or WSAGetLastError() (Windows)
     */
    static Socket::Status getErrorStatus();
};
} // namespace sck::impl