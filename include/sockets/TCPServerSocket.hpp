#pragma once

#include "sockets/IPAddress.hpp"
#include "sockets/Socket.hpp"
#include "sockets/SocketImpl.hpp"
#include "sockets/TCPClientSocket.hpp"

namespace sck
{

class TCPServerSocket : public Socket
{
  public:
    TCPServerSocket();
    ~TCPServerSocket();

    [[nodiscard]] Status listen(const unsigned short port, const IPAddress &address = IPAddress::Any);
    void close();
    [[nodiscard]] Status accept(TCPClientSocket &socket);
};

} // namespace sck