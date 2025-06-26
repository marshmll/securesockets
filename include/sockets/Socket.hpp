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
class Socket
{
  public:
    Socket(const int domain, const int type, const int protocol = 0);
    virtual ~Socket();

    int setOpt(const int level, const int optname, const void *optval, const socklen_t optlen);
    int bind(const unsigned short port);
    bool good() const;
    virtual void close();

    static const std::string getErrorMsg();

  protected:
    int sockFd;
};
} // namespace sck

#endif // SOCKET_H