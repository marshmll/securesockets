#ifndef SECURETCPCLIENT_H
#define SECURETCPCLIENT_H

#include <arpa/inet.h>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "securesockets/SocketUtils.hpp"

namespace sck
{
constexpr int ANY_PORT = 0;

class SecureTCPClient
{
  public:
    SecureTCPClient();
    SecureTCPClient(const SecureTCPClient &) = delete;
    SecureTCPClient &operator=(const SecureTCPClient &) = delete;

    ~SecureTCPClient();

    [[nodiscard]]
    const bool connect(const std::string &server_addr, const unsigned short int server_port);

    [[nodiscard]]
    const int send(const char *data, const size_t size);

    [[nodiscard]]
    const int recv(char *const buffer, const size_t size);

  private:
    void nullifyHandles();

    std::string serverAddr;
    unsigned short int serverPort;

    int err;
    int sd;
    sockaddr_in sa;
    SSL_CTX *ctx;
    SSL *ssl;
    X509 *serverCert;
    char *str;
    const SSL_METHOD *meth;
};
} // namespace sck

#endif // SECURETCPCLIENT_H