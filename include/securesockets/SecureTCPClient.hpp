#ifndef SECURETCPCLIENT_H
#define SECURETCPCLIENT_H

#include <arpa/inet.h>   // sockaddr_in, inet_pton
#include <fcntl.h>       // fcntl
#include <filesystem>    // std::filesystem
#include <iostream>      // std::cout
#include <memory>        // std::unique_ptr
#include <netinet/in.h>  // sockaddr_in, htons
#include <openssl/err.h> // ERR_print_errors_fp, ERR_get_error
#include <openssl/ssl.h> // SSL, SSL_CTX, SSL_METHOD
#include <openssl/x509v3.h> // X509, sk_GENERAL_NAME_num, GENERAL_NAME, sk_GENERAL_NAME_value, GEN_DNS, GEN_IPADD, GENERAL_NAME_free
#include <stdexcept>    // std::runtime_error
#include <string>       // std::string
#include <sys/socket.h> // socket, connect
#include <unistd.h>     // close

namespace sck
{
constexpr int ANY_PORT = 0;
constexpr int INVALID_SOCKET = -1;

class SecureTCPClient
{
  public:
    SecureTCPClient(const std::filesystem::path &ca_cert_path);
    SecureTCPClient(const SecureTCPClient &) = delete;
    SecureTCPClient &operator=(const SecureTCPClient &) = delete;
    SecureTCPClient(SecureTCPClient &&) = delete;
    SecureTCPClient &operator=(SecureTCPClient &&) = delete;

    ~SecureTCPClient();

    bool connect(const std::string &server_addr, const unsigned short int server_port,
                 const long int timeout_seconds = -1);
    int send(const char *data, const size_t size);
    int recv(char *buf, const size_t size);
    int sendNonBlocking(const char *data, const size_t size);
    int recvNonBlocking(char *buf, const size_t size);
    int getSocketFD() const;

  private:
    void nullifyHandles();
    void initSSL();
    void initRawSocket();
    void logConnectionDetails();
    std::string getOpenSSLError() const;
    std::string getSSLError(int err_code) const;
    bool verifyServerCertificate();
    bool verifyHostname(X509 *cert);
    bool matchHostname(const std::string &pattern, const std::string &hostname);
    bool checkCertificateValidity(X509 *cert);

    std::string caCertPath;
    std::string serverAddr;
    unsigned short serverPort;
    int sd;
    SSL_CTX *ctx;
    SSL *ssl;
    const SSL_METHOD *meth;
};
} // namespace sck

#endif // SECURETCPCLIENT_H