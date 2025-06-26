#ifndef SOCKET_H
#define SOCKET_H

#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <unistd.h>

namespace sck
{
class TCPSocket
{
  public:
    TCPSocket();
    ~TCPSocket();

    bool init(const int protocol = 0);
    int setOpt(const int level, const int optname, const void *optval, const socklen_t optlen);
    int bind(const unsigned short port);
    int listen(const int n);
    int connect(const std::string &host, const unsigned short port);
    int accept();
    size_t send(const void *data, const size_t size, const int flags = 0);
    size_t recv(void *const buf, const size_t size, const int flags = 0);
    void close();

    static const std::string getErrorMsg();

  private:
    int sockFd;
    int connFd;
};
} // namespace sck

#endif // SOCKET_H