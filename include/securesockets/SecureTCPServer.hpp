#ifndef SECURETCPSERVER_H
#define SECURETCPSERVER_H

#include <arpa/inet.h>      // sockaddr_in, inet_ntop
#include <cstring>          // strerror, memset
#include <filesystem>       // std::filesystem::path
#include <iostream>         // std::cout
#include <netinet/in.h>     // sockaddr_in, INADDR_ANY
#include <openssl/err.h>    // ERR_print_errors_fp
#include <openssl/ssl.h>    // SSL, SSL_CTX
#include <openssl/x509v3.h> // X509
#include <stdexcept>        // runtime_error
#include <string>           // string
#include <sys/socket.h>     // socket, bind, listen
#include <unistd.h>         // close

namespace sck
{

class SecureTCPServer
{
  public:
    SecureTCPServer(const std::filesystem::path &cert_path, const std::filesystem::path &priv_key_path);
    SecureTCPServer(const SecureTCPServer &) = delete;
    SecureTCPServer &operator=(const SecureTCPServer &) = delete;
    ~SecureTCPServer();

    bool listen(unsigned short port, unsigned int queue_size = 5);
    bool accept();
    int recv(char *buf, size_t size);
    int send(const char *data, size_t size);
    bool isListening() const;
    int getSocketFD() const;

  private:
    void nullifyHandles();
    void logConnectionDetails();
    std::string getOpenSSLError() const;
    std::string getSSLError(int err_code) const;

    int listenSd = -1;
    int sd = -1;
    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
    const SSL_METHOD *meth = nullptr;
    std::filesystem::path certPath;
    std::filesystem::path privKeyPath;
};

} // namespace sck

#endif // SECURETCPSERVER_H