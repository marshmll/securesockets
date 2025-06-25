#ifndef SECURETCPSERVER_H
#define SECURETCPSERVER_H

#include <filesystem>
#include <iostream>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>

#include "securesockets/SocketUtils.hpp"

namespace sck
{
class SecureTCPServer
{
  public:
    SecureTCPServer(const std::filesystem::path &cert_path, const std::filesystem::path &priv_key_path);
    SecureTCPServer(const SecureTCPServer &) = delete;
    SecureTCPServer &operator=(const SecureTCPServer &) = delete;
    ~SecureTCPServer();

    [[nodiscard]]
    const bool listen(const unsigned short int port, const unsigned int queue_size = 5);

    [[nodiscard]]
    const bool accept();

    const int recv(char *const buf, const size_t size);

    const int send(const char *data, const size_t size);

  private:
    int err;
    int listenSd;
    int sd;
    sockaddr_in saServer;
    sockaddr_in saClient;
    socklen_t clientLen;
    SSL_CTX *ctx;
    SSL *ssl;
    X509 *clientCert;
    char *str;
    char buf[4096];
    const SSL_METHOD *meth;

    std::filesystem::path certPath;
    std::filesystem::path privKeyPath;

    void nullifyHandles();
};
} // namespace sck

#endif // SECURETCPSERVER_H