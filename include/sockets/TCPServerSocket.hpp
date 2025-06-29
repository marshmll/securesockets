#pragma once

#include "sockets/IPAddress.hpp"
#include "sockets/Socket.hpp"
#include "sockets/SocketImpl.hpp"
#include "sockets/TCPClientSocket.hpp"

namespace sck
{
/**
 * @class TCPServerSocket
 * @brief TCP server socket implementation for connection-oriented communication
 *
 * This class provides a TCP server socket that:
 * - Listens for incoming connections on a specified port
 * - Accepts client connections into TCPClientSocket instances
 * - Manages socket resources automatically
 * - Handles both IPv4 addresses
 *
 * @note Inherits from Socket for basic socket functionality
 * @warning Not thread-safe - concurrent operations require external synchronization
 */
class TCPServerSocket : public Socket
{
  public:
    /**
     * @brief Construct a new TCPServerSocket object
     * @post Creates a TCP socket in uninitialized state
     */
    TCPServerSocket();

    /**
     * @brief Destroy the TCPServerSocket object
     * @note Automatically closes the socket if still open
     */
    ~TCPServerSocket();

    /**
     * @brief Start listening for incoming connections
     * @param port The port number to listen on
     * @param address The local address to bind to (default: Any/INADDR_ANY)
     * @return Status operation result:
     *         - Status::Ready: Successfully listening
     *         - Status::Error: Binding or listening failed
     *
     * @note Performs the following operations:
     *       1. Creates a new socket if needed
     *       2. Binds to the specified address and port
     *       3. Starts listening with SOMAXCONN backlog
     * @warning Fails if address is IPAddress::Broadcast
     * @warning Prints error messages to stderr on failure
     */
    [[nodiscard]] Status listen(const unsigned short port, const IPAddress &address = IPAddress::Any);

    /**
     * @brief Close the listening socket
     * @post Socket is closed and can no longer accept connections
     * @note Safe to call on already closed sockets
     * @note Delegates to Socket::close()
     */
    void close();

    /**
     * @brief Accept an incoming client connection
     * @param socket TCPClientSocket that will handle the new connection
     * @return Status operation result:
     *         - Status::Ready: Client successfully accepted
     *         - Status::Error: Accept failed or socket not listening
     *
     * @note The provided client socket will be:
     *       1. Closed if already open
     *       2. Initialized with the new connection
     * @warning Prints error messages to stderr on failure
     * @warning Blocks until a connection arrives (in blocking mode)
     */
    [[nodiscard]] Status accept(TCPClientSocket &socket);
};
} // namespace sck