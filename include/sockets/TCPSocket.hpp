#ifndef TCPSOCKET_H
#define TCPSOCKET_H

#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <unistd.h>

#include "securesockets/Socket.hpp"

namespace sck
{
class TCPSocket : public Socket
{
  public:
    TCPSocket();
    ~TCPSocket();

    int listen(const int n);
    int connect(const std::string &host, const unsigned short port);
    int accept();
    ssize_t send(const void *data, const size_t size, const int flags = 0);
    ssize_t recv(void *const buf, const size_t size, const int flags = 0);
    void close() override;

  private:
    int connFd;
};
} // namespace sck

#endif // TCPSOCKET_H