#include "securesockets/SecureTCPServer.hpp"

using namespace sck;

SecureTCPServer::SecureTCPServer(const std::filesystem::path &cert_path, const std::filesystem::path &priv_key_path)
    : certPath(cert_path), privKeyPath(priv_key_path)
{
    nullifyHandles();

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    meth = TLS_server_method();
    ctx = SSL_CTX_new(meth);

    if (!ctx)
    {
        throw std::runtime_error("[SecureTCPServer] Failed to create SSL context: " + getOpenSSLError());
    }
}

SecureTCPServer::~SecureTCPServer()
{
    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
    }
    if (sd >= 0)
    {
        close(sd);
        sd = -1;
    }
    if (listenSd >= 0)
    {
        close(listenSd);
        listenSd = -1;
    }
}

bool SecureTCPServer::listen(unsigned short port, unsigned int queue_size)
{
    if (listenSd >= 0)
    {
        throw std::runtime_error("[SecureTCPServer] Server is already listening");
    }

    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        throw std::runtime_error("[SecureTCPServer] Failed to load certificate: " + getOpenSSLError());
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, privKeyPath.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        throw std::runtime_error("[SecureTCPServer] Failed to load private key: " + getOpenSSLError());
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        throw std::runtime_error("[SecureTCPServer] Private key doesn't match certificate");
    }

    // Create and bind socket
    listenSd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSd < 0)
    {
        throw std::runtime_error("[SecureTCPServer] Failed to create socket: " + std::string(strerror(errno)));
    }

    // Set SO_REUSEADDR
    int optval = 1;
    setsockopt(listenSd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in saServer;
    memset(&saServer, 0, sizeof(saServer));
    saServer.sin_family = AF_INET;
    saServer.sin_addr.s_addr = INADDR_ANY;
    saServer.sin_port = htons(port);

    if (bind(listenSd, (struct sockaddr *)&saServer, sizeof(saServer)))
    {
        close(listenSd);
        listenSd = -1;
        throw std::runtime_error("[SecureTCPServer] Failed to bind socket: " + std::string(strerror(errno)));
    }

    if (::listen(listenSd, queue_size))
    {
        close(listenSd);
        listenSd = -1;
        throw std::runtime_error("[SecureTCPServer] Failed to listen: " + std::string(strerror(errno)));
    }

    return true;
}

bool SecureTCPServer::accept()
{
    if (listenSd < 0)
    {
        throw std::runtime_error("[SecureTCPServer] Server is not listening");
    }

    struct sockaddr_in saClient;
    socklen_t clientLen = sizeof(saClient);

    // Clear any existing SSL connection first
    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
    }
    if (sd >= 0)
    {
        close(sd);
        sd = -1;
    }

    sd = ::accept(listenSd, (struct sockaddr *)&saClient, &clientLen);
    if (sd < 0)
    {
        throw std::runtime_error("[SecureTCPServer] Failed to accept connection: " + std::string(strerror(errno)));
    }

    // Log connection info
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &saClient.sin_addr, clientIP, INET_ADDRSTRLEN);
    std::cout << "[SecureTCPServer] Connection from " << clientIP << " port " << ntohs(saClient.sin_port) << "\n";

    // SSL negotiation
    ssl = SSL_new(ctx);
    if (!ssl)
    {
        close(sd);
        sd = -1;
        throw std::runtime_error("[SecureTCPServer] Failed to create SSL structure: " + getOpenSSLError());
    }

    SSL_set_fd(ssl, sd);

    int err = SSL_accept(ssl);
    if (err <= 0)
    {
        int ssl_err = SSL_get_error(ssl, err);
        SSL_free(ssl);
        ssl = nullptr;
        close(sd);
        sd = -1;
        throw std::runtime_error("[SecureTCPServer] SSL handshake failed: " + getSSLError(ssl_err));
    }

    logConnectionDetails();
    return true;
}

int SecureTCPServer::recv(char *buf, size_t size)
{
    if (!ssl)
    {
        throw std::runtime_error("[SecureTCPServer] Not connected");
    }

    if (size == 0)
    {
        return 0;
    }

    int received = SSL_read(ssl, buf, size - 1);
    if (received <= 0)
    {
        throw std::runtime_error("[SecureTCPServer] Receive failed: " + getSSLError(SSL_get_error(ssl, received)));
    }

    buf[received] = '\0';
    return received;
}

int SecureTCPServer::send(const char *data, size_t size)
{
    if (!ssl)
    {
        throw std::runtime_error("[SecureTCPServer] Not connected");
    }

    int sent = SSL_write(ssl, data, size);
    if (sent <= 0)
    {
        throw std::runtime_error("[SecureTCPServer] Send failed: " + getSSLError(SSL_get_error(ssl, sent)));
    }
    return sent;
}

bool SecureTCPServer::isListening() const
{
    return (listenSd >= 0) && (ctx != nullptr);
}

int SecureTCPServer::getSocketFD() const
{
    return sd;
}

void SecureTCPServer::nullifyHandles()
{
    ctx = nullptr;
    ssl = nullptr;
    meth = nullptr;
}

void SecureTCPServer::logConnectionDetails()
{
    if (!ssl)
    {
        std::cerr << "[SecureTCPServer] Error: No SSL connection\n";
        return;
    }

    // Basic connection info
    std::cout << "[SecureTCPServer] SSL Connection Details:\n";
    std::cout << "  Protocol: " << SSL_get_version(ssl) << "\n";
    std::cout << "  Cipher: " << SSL_get_cipher(ssl) << " (strength: " << SSL_get_cipher_bits(ssl, nullptr)
              << " bits)\n";

    // Client certificate info
    X509 *clientCert = SSL_get_peer_certificate(ssl);
    if (!clientCert)
    {
        std::cout << "  Client Authentication: No certificate presented\n";
        return;
    }

    // Subject information
    X509_NAME *subject = X509_get_subject_name(clientCert);
    if (subject)
    {
        std::cout << "  Client Certificate:\n";

        // Improved subject display using X509_NAME_print_ex
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio)
        {
            X509_NAME_print_ex(bio, subject, 0, XN_FLAG_RFC2253);
            char *buf = nullptr;
            long len = BIO_get_mem_data(bio, &buf);
            if (buf && len > 0)
            {
                std::cout << "    Subject: " << std::string(buf, len) << "\n";
            }
            BIO_free(bio);
        }
    }

    // Issuer information
    X509_NAME *issuer = X509_get_issuer_name(clientCert);
    if (issuer)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio)
        {
            X509_NAME_print_ex(bio, issuer, 0, XN_FLAG_RFC2253);
            char *buf = nullptr;
            long len = BIO_get_mem_data(bio, &buf);
            if (buf && len > 0)
            {
                std::cout << "    Issuer: " << std::string(buf, len) << "\n";
            }
            BIO_free(bio);
        }
    }

    // Validity period
    ASN1_TIME *notBefore = X509_get_notBefore(clientCert);
    ASN1_TIME *notAfter = X509_get_notAfter(clientCert);
    if (notBefore && notAfter)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio)
        {
            std::cout << "    Validity:\n";

            ASN1_TIME_print(bio, notBefore);
            char *from = nullptr;
            long from_len = BIO_get_mem_data(bio, &from);
            if (from)
            {
                std::cout << "      Not Before: " << std::string(from, from_len) << "\n";
            }

            BIO_reset(bio);
            ASN1_TIME_print(bio, notAfter);
            char *to = nullptr;
            long to_len = BIO_get_mem_data(bio, &to);
            if (to)
            {
                std::cout << "      Not After:  " << std::string(to, to_len) << "\n";
            }
            BIO_free(bio);
        }
    }

    // Certificate extensions (SANs)
    STACK_OF(GENERAL_NAME) *sans =
        static_cast<STACK_OF(GENERAL_NAME) *>(X509_get_ext_d2i(clientCert, NID_subject_alt_name, nullptr, nullptr));
    if (sans)
    {
        std::cout << "    Subject Alternative Names:\n";
        int count = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < count; i++)
        {
            GENERAL_NAME *name = sk_GENERAL_NAME_value(sans, i);
            if (name->type == GEN_DNS)
            {
                std::cout << "      DNS: " << ASN1_STRING_get0_data(name->d.dNSName) << "\n";
            }
            else if (name->type == GEN_IPADD)
            {
                char ip[INET6_ADDRSTRLEN];
                if (name->d.iPAddress->length == 4)
                {
                    inet_ntop(AF_INET, name->d.iPAddress->data, ip, sizeof(ip));
                    std::cout << "      IPv4: " << ip << "\n";
                }
                else if (name->d.iPAddress->length == 16)
                {
                    inet_ntop(AF_INET6, name->d.iPAddress->data, ip, sizeof(ip));
                    std::cout << "      IPv6: " << ip << "\n";
                }
            }
        }
        sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
    }

    // Fingerprints
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n;
    if (X509_digest(clientCert, EVP_sha1(), md, &n))
    {
        std::cout << "    SHA1 Fingerprint: ";
        for (unsigned int i = 0; i < n; i++)
        {
            printf("%02X", md[i]);
            if (i + 1 < n)
                printf(":");
        }
        std::cout << "\n";
    }

    if (X509_digest(clientCert, EVP_sha256(), md, &n))
    {
        std::cout << "    SHA256 Fingerprint: ";
        for (unsigned int i = 0; i < n; i++)
        {
            printf("%02X", md[i]);
            if (i + 1 < n)
                printf(":");
        }
        std::cout << "\n";
    }

    X509_free(clientCert);
}

std::string SecureTCPServer::getOpenSSLError() const
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = nullptr;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    return ret;
}

std::string SecureTCPServer::getSSLError(int err_code) const
{
    switch (err_code)
    {
    case SSL_ERROR_NONE:
        return "No error";
    case SSL_ERROR_ZERO_RETURN:
        return "Connection closed";
    case SSL_ERROR_WANT_READ:
        return "SSL wants read";
    case SSL_ERROR_WANT_WRITE:
        return "SSL wants write";
    case SSL_ERROR_WANT_CONNECT:
        return "SSL wants connect";
    case SSL_ERROR_WANT_ACCEPT:
        return "SSL wants accept";
    case SSL_ERROR_WANT_X509_LOOKUP:
        return "SSL wants X509 lookup";
    case SSL_ERROR_SYSCALL:
        return "I/O error: " + std::string(strerror(errno));
    case SSL_ERROR_SSL:
        return getOpenSSLError();
    default:
        return "Unknown SSL error";
    }
}
