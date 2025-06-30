#pragma once

#include "sockets/SocketHandle.hpp"

#include <cstring>

namespace sck
{
/**
 * @class Socket
 * @brief Base class for network socket operations
 *
 * This class provides the common interface and functionality for both TCP and UDP sockets.
 * It handles socket creation, blocking mode, and basic socket operations while managing
 * the underlying socket handle.
 */
class Socket
{
  public:
    /**
     * @enum Status
     * @brief Represents the status of socket operations
     */
    enum class Status
    {
        Ready,        ///< Operation completed successfully
        WouldBlock,   ///< Operation would block (non-blocking mode only)
        Partial,      ///< Partial data was sent/received
        Disconnected, ///< The remote host closed the connection
        Error,        ///< An unexpected error occurred
        SSLError      ///< An SSL related error occurred
    };

    /**
     * @brief Special port value indicating the system should assign a random available port
     */
    static constexpr unsigned short RandomPort = 0;

    /**
     * @brief Virtual destructor to allow proper cleanup in derived classes
     */
    virtual ~Socket();

    // Delete copy operations to prevent socket duplication
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;

    /**
     * @brief Move constructor
     * @param socket The socket to move from
     */
    Socket(Socket &&socket) noexcept;

    /**
     * @brief Move assignment operator
     * @param socket The socket to move from
     * @return Reference to this socket
     */
    Socket &operator=(Socket &&socket) noexcept;

    /**
     * @brief Get the port this socket is bound to
     * @return The bound port number, or 0 if not bound or error occurred
     */
    [[nodiscard]] unsigned short getBoundPort() const;

    /**
     * @brief Sets the blocking mode of the socket
     * @param blocking True to enable blocking mode, false for non-blocking
     */
    void setBlocking(const bool blocking);

    /**
     * @brief Checks if the socket is in blocking mode
     * @return True if the socket is blocking, false otherwise
     */
    [[nodiscard]] bool isBlocking() const;

  protected:
    /**
     * @enum Type
     * @brief The type of socket (TCP or UDP)
     */
    enum class Type
    {
        TCP, ///< Stream-oriented TCP socket
        UDP  ///< Datagram-oriented UDP socket
    };

    /**
     * @brief Constructs a socket of the specified type
     * @param type The type of socket to create (TCP or UDP)
     */
    explicit Socket(Type type);

     /**
     * @brief Constructs a socket of the specified type
     * @param type The type of socket to create (TCP or UDP)
     */
    explicit Socket(Type type, SocketHandle handle, bool blocking);

    /**
     * @brief Gets the underlying system socket handle
     * @return The native socket handle
     */
    [[nodiscard]] SocketHandle getSystemHandle() const;

    /**
     * @brief Creates a new socket
     */
    void create();

    /**
     * @brief Creates a socket wrapper for an existing handle
     * @param handle An existing native socket handle to wrap
     */
    virtual void create(SocketHandle handle);

    /**
     * @brief Closes the socket
     */
    virtual void close();

  private:
    Type type;           ///< The socket type (TCP/UDP)
    SocketHandle handle; ///< The native socket handle
    bool blocking;       ///< Current blocking mode

    friend class SSLSocket;
};
} // namespace sck