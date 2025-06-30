#pragma once

#include "sockets/IPAddress.hpp"
#include "sockets/Socket.hpp"
#include "sockets/SocketImpl.hpp"

#include <optional>

namespace sck
{
/**
 * @class TCPClientSocket
 * @brief TCP client socket implementation for connection-oriented communication
 *
 * This class provides a TCP client socket that:
 * - Manages connections to remote servers
 * - Supports both blocking and non-blocking operations
 * - Implements timeout support for connection establishment
 * - Handles partial sends and receives
 * - Provides remote endpoint information
 *
 * @note Inherits from Socket for basic socket functionality
 * @warning In non-blocking mode, partial sends require manual retry handling
 */
class TCPClientSocket : public Socket
{
  public:
    /**
     * @brief Construct a new TCPClientSocket object
     * @post Creates a TCP socket in unconnected state
     */
    TCPClientSocket();

    /**
     * @brief Destroy the TCPClientSocket object
     * @note Automatically disconnects if still connected
     */
    virtual ~TCPClientSocket();

    /**
     * @brief Get the remote server's IP address
     * @return std::optional<IPAddress> Remote address if connected, empty otherwise
     * @note Uses getpeername() internally
     */
    [[nodiscard]] std::optional<IPAddress> getRemoteAddress() const;

    /**
     * @brief Get the remote server's port number
     * @return unsigned short Remote port if connected, 0 otherwise
     * @note Uses getpeername() and ntohs() conversion
     */
    [[nodiscard]] unsigned short getRemotePort() const;

    /**
     * @brief Connect to a remote server
     * @param remote_address Server IP address
     * @param remote_port Server port number
     * @param timeout_ms Connection timeout in milliseconds (0 = blocking connect)
     * @return Status Connection result:
     *         - Status::Ready: Connection established
     *         - Status::Error: Connection failed
     *         - Status::Blocked: Connection in progress (non-blocking mode)
     *
     * @note For timeout > 0:
     *       - Temporarily switches to non-blocking mode
     *       - Uses select() for timeout implementation
     *       - Restores original blocking mode
     * @warning Timeout precision depends on system scheduler
     */
    [[nodiscard]] virtual Status connect(IPAddress remote_address, unsigned short remote_port,
                                         unsigned int timeout_ms = 0);

    /**
     * @brief Disconnect from the remote server
     * @post Closes the socket and resets connection state
     * @note Safe to call on already disconnected sockets
     */
    virtual void disconnect();

    /**
     * @brief Send data to the remote server
     * @param data Pointer to data buffer
     * @param size Size of data in bytes
     * @param timeout_ms Timeout in milliseconds (blocking mode)
     * @return Status Transmission result:
     *         - Status::Ready: All data sent
     *         - Status::Partial: Partial data sent (non-blocking mode)
     *         - Status::Error: Send failed
     *
     * @warning In non-blocking mode, prints warning about partial sends
     * @note For better partial send handling, use send() with 'sent' parameter
     */
    [[nodiscard]] virtual Status send(const void *data, size_t size, const unsigned int timeout_ms = 0);

    /**
     * @brief Send data to the remote server with progress tracking
     * @param data Pointer to data buffer
     * @param size Size of data in bytes
     * @param sent [out] Actual number of bytes sent
     * @param timeout_ms Timeout in milliseconds (blocking mode)
     * @return Status Transmission result:
     *         - Status::Ready: All data sent
     *         - Status::Partial: Partial data sent (non-blocking mode)
     *         - Status::Error: Send failed
     *
     * @note Implements send loop for partial transmissions
     * @warning Buffer must remain valid during entire send operation
     */
    [[nodiscard]] virtual Status send(const void *data, size_t size, size_t &sent, const unsigned int timeout_ms = 0);

    /**
     * @brief Receive data from the remote server
     * @param data Pointer to receive buffer
     * @param size Maximum bytes to receive
     * @param received [out] Actual number of bytes received
     * @param timeout_ms Timeout in milliseconds (blocking mode)
     * @return Status Reception result:
     *         - Status::Ready: Data received
     *         - Status::Disconnected: Remote closed connection
     *         - Status::Error: Receive error
     *         - Status::WouldBlock: No data available (non-blocking mode)
     *
     * @note Single call to recv(), may need multiple calls for complete message
     */
    [[nodiscard]] virtual Status recv(void *data, size_t size, size_t &received, const unsigned int timeout_ms = 0);

    using Socket::close;
    using Socket::create;

  private:
#ifdef __WIN32__
    static constexpr int flags = 0; ///< Windows socket flags (no special behavior)
#else
    static constexpr int flags = MSG_NOSIGNAL; ///< Prevents SIGPIPE on Linux/macOS
#endif
};
} // namespace sck