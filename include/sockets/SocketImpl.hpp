#pragma once

#include <sockets/Socket.hpp>
#include <sockets/SocketHandle.hpp>

#ifdef __WIN32__

#include "sockets/Windows/Headers.hpp"
#include "sockets/Windows/WinSock2.hpp"

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
    static constexpr UINT_PTR InvalidHandle = INVALID_SOCKET;
#else
    using AddrLen = socklen_t;
    static constexpr int InvalidHandle = -1;
#endif

    /**
     * @brief Creates a sockaddr_in structure for IPv4 addresses
     *
     * @param addr The IPv4 address in host byte order
     * @param port The port number in host byte order
     * @return sockaddr_in Initialized address structure in network byte order
     */
    [[nodiscard]] static sockaddr_in createAddress(const uint32_t addr, const unsigned short port);

    /**
     * @brief Checks if a socket handle is valid
     *
     * @param handle The socket handle to check
     * @return true if the handle is valid
     * @return false if the handle is invalid
     */
    [[nodiscard]] static bool isValidHandle(SocketHandle handle);

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

    [[nodiscard]] static int waitRead(SocketHandle handle, const unsigned int timeout_ms = 0);

    [[nodiscard]] static int waitWrite(SocketHandle handle, const unsigned int timeout_ms = 0);

    /**
     * @brief Gets the status corresponding to the last socket error
     *
     * @return Socket::Status The status corresponding to the last error:
     *         - Socket::Status::Done on success
     *         - Appropriate error status based on errno (Unix) or WSAGetLastError() (Windows)
     */
    [[nodiscard]] static Socket::Status getLastStatus();

    [[nodiscard]] static const char *getLastError();
};
} // namespace sck::impl