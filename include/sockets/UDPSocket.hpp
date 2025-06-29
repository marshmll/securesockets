#pragma once

#include "sockets/IPAddress.hpp"
#include "sockets/Socket.hpp"
#include "sockets/SocketImpl.hpp"

#include <cstddef>
#include <cstring>
#include <iostream>
#include <vector>

namespace sck
{
/**
 * @class UDPSocket
 * @brief UDP (User Datagram Protocol) socket implementation
 *
 * This class provides a UDP socket interface supporting:
 * - Connectionless datagram communication
 * - Sending/receiving datagrams to/from any host
 * - Port binding for receiving datagrams
 * - Broadcast support (when explicitly enabled)
 *
 * @note UDP is connectionless and doesn't guarantee delivery or ordering
 * @warning Maximum datagram size is limited to 65507 bytes (MaxDatagramUsableSize)
 * @extends Socket
 */
class UDPSocket : public Socket
{
  public:
    /**
     * @brief Maximum usable datagram size (payload limit for UDP over IPv4)
     *
     * Theoretical maximum is 65507 bytes calculated as:
     * 65535 (max UDP packet size) - 20 (IP header) - 8 (UDP header)
     */
    static constexpr size_t MaxDatagramUsableSize = 65507;

    /**
     * @brief Construct a new UDPSocket object
     */
    UDPSocket();

    /**
     * @brief Destroy the UDPSocket object
     *
     * Automatically closes the socket if still open
     */
    ~UDPSocket();

    /**
     * @brief Move constructor
     * @param socket The socket to move from
     */
    UDPSocket(UDPSocket &&socket) noexcept = default;

    /**
     * @brief Move assignment operator
     * @param socket The socket to move from
     * @return Reference to this socket
     */
    UDPSocket &operator=(UDPSocket &&socket) noexcept = default;

    /**
     * @brief Bind the socket to a specific port and address
     * @param port The port to bind to (use 0 for OS-assigned port)
     * @param address The IP address to bind to (default: OSDefined)
     * @return Status::Ready on success, Status::Error on failure
     *
     * @note Binding to IPAddress::Broadcast will fail
     * @note Subsequent calls will close and recreate the socket
     */
    [[nodiscard]] Status bind(const unsigned short port, const IPAddress &address = IPAddress::Any);

    /**
     * @brief Unbind the socket from its port
     *
     * Equivalent to calling close()
     */
    void unbind();

    /**
     * @brief Send a datagram to a remote host
     * @param data Pointer to the data to send
     * @param size Size of the data in bytes
     * @param ip Destination IP address
     * @param port Destination port
     * @return Status::Ready on success, error status on failure
     *
     * @throws None but returns Status::Error if:
     * - Data exceeds MaxDatagramUsableSize
     * - Socket cannot be created
     */
    [[nodiscard]] Status send(const void *data, const size_t size, const IPAddress &ip, const unsigned short port);

    /**
     * @brief Receive a datagram from any host
     * @param buf Buffer to store received data
     * @param size Size of the buffer
     * @param received [out] Actual number of bytes received
     * @param remote_ip [out] Sender's IP address
     * @param port [out] Sender's port number
     * @return Status::Ready on success, Status::Error on invalid buffer
     *
     * @note This is a non-blocking operation by default (check parent's blocking mode)
     * @warning Buffer must be at least MaxDatagramUsableSize bytes to avoid truncation
     */
    [[nodiscard]] Status recv(void *const buf, const size_t size, size_t &received, IPAddress &remote_ip,
                              unsigned short &port);
};
} // namespace sck