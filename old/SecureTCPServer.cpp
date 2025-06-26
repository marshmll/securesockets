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
        std::cerr << "[SecureTCPServer] Server is already listening" << std::endl;
        return false;
    }

    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "[SecureTCPServer] Failed to load certificate: " << getOpenSSLError() << std::endl;
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, privKeyPath.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "[SecureTCPServer] Failed to load private key: " << getOpenSSLError() << std::endl;
        return false;
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        std::cerr << "[SecureTCPServer] Private key doesn't match certificate" << std::endl;
        return false;
    }

    // Create and bind socket
    listenSd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSd < 0)
    {
        std::cerr << "[SecureTCPServer] Failed to create socket: " << std::string(strerror(errno)) << std::endl;
        return false;
    }

    // Set SO_REUSEADDR
    int optval = 1;
    setsockopt(listenSd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in saServer;
    memset(&saServer, 0, sizeof(saServer));
    saServer.sin_family = AF_INET;
    saServer.sin_addr.s_addr = INADDR_ANY;
    saServer.sin_port = htons(port);

    if (bind(listenSd, (struct sockaddr *)&saServer, sizeof(saServer)) < 0)
    {
        close(listenSd);
        listenSd = -1;
        std::cerr << "[SecureTCPServer] Failed to bind socket: " << std::string(strerror(errno)) << std::endl;
        return false;
    }

    if (::listen(listenSd, queue_size) < 0)
    {
        close(listenSd);
        listenSd = -1;
        std::cerr << "[SecureTCPServer] Failed to listen: " << std::string(strerror(errno)) << std::endl;
        return false;
    }

    return true;
}

bool SecureTCPServer::accept(const long int timeout_seconds)
{
    if (listenSd < 0)
    {
        std::cerr << "[SecureTCPServer] Server is not listening" << std::endl;
        return false;
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

    // Blocking mode if timeout is negative
    if (timeout_seconds < 0)
    {
        // Non-blocking mode with timeout
        int flags = fcntl(listenSd, F_GETFL, 0);
        if (flags < 0)
        {
            std::cerr << "[SecureTCPServer] Failed to get socket flags: " << strerror(errno) << std::endl;
            return false;
        }

        // Only change if in non-blocking mode
        if ((flags & O_NONBLOCK) == 0)
        {
            if (fcntl(listenSd, F_SETFL, flags & ~O_NONBLOCK) < 0)
            {
                std::cerr << "[SecureTCPServer] Failed to set socket to blocking mode: " << strerror(errno)
                          << std::endl;
                return false;
            }
        }

        // Accept new connection (blocking)
        sd = ::accept(listenSd, (struct sockaddr *)&saClient, &clientLen);

        if (sd < 0)
        {
            std::cerr << "[SecureTCPServer] Failed to accept connection: " << strerror(errno) << std::endl;
            return false;
        }
    }
    else
    {
        // Non-blocking mode with timeout
        int flags = fcntl(listenSd, F_GETFL, 0);
        if (flags < 0)
        {
            std::cerr << "[SecureTCPServer] Failed to get socket flags: " << strerror(errno) << std::endl;
            return false;
        }

        // Only change if in blocking mode
        if ((flags & O_NONBLOCK) != O_NONBLOCK)
        {
            if (fcntl(listenSd, F_SETFL, flags | O_NONBLOCK) < 0)
            {
                std::cerr << "[SecureTCPServer] Failed to set socket to non-blocking mode: " << strerror(errno)
                          << std::endl;
                return false;
            }
        }

        // Accept new connection with timeout
        time_t start_time = time(nullptr);
        do
        {
            sd = ::accept(listenSd, (struct sockaddr *)&saClient, &clientLen);

            if (sd < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    // No connection available yet, wait with select
                    fd_set read_fds;
                    FD_ZERO(&read_fds);
                    FD_SET(listenSd, &read_fds);

                    struct timeval timeout;
                    timeout.tv_sec = 1; // Check every second
                    timeout.tv_usec = 0;

                    int select_result = select(listenSd + 1, &read_fds, nullptr, nullptr, &timeout);
                    if (select_result < 0)
                    {
                        std::cerr << "[SecureTCPServer] Select failed: " << strerror(errno) << std::endl;
                        return false;
                    }
                    else if (select_result == 0)
                    {
                        // Timeout, check if we've exceeded our total timeout
                        if (time(nullptr) - start_time > timeout_seconds)
                        {
                            std::cerr << "[SecureTCPServer] Accept timeout" << std::endl;
                            return false;
                        }
                        continue;
                    }
                    // Socket is ready, try accept again
                    continue;
                }
                else
                {
                    // Real accept error
                    std::cerr << "[SecureTCPServer] Failed to accept connection: " << strerror(errno) << std::endl;
                    return false;
                }
            }
        } while (sd < 0);
    }

    // Log connection info
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &saClient.sin_addr, clientIP, INET_ADDRSTRLEN);
    std::cout << "[SecureTCPServer] Connection from " << clientIP << " port " << ntohs(saClient.sin_port) << std::endl;

    // SSL negotiation (same for both blocking and non-blocking modes)
    ssl = SSL_new(ctx);
    if (!ssl)
    {
        std::cerr << "[SecureTCPServer] Failed to create SSL structure: " << getOpenSSLError() << std::endl;
        close(sd);
        sd = -1;
        return false;
    }

    SSL_set_fd(ssl, sd);

    if (timeout_seconds < 0)
    {
        // Blocking SSL handshake
        int err = SSL_accept(ssl);
        if (err <= 0)
        {
            int ssl_err = SSL_get_error(ssl, err);
            std::cerr << "[SecureTCPServer] SSL handshake failed: " << getSSLError(ssl_err) << std::endl;
            SSL_free(ssl);
            ssl = nullptr;
            close(sd);
            sd = -1;
            return false;
        }
    }
    else
    {
        // Non-blocking SSL handshake with timeout
        time_t ssl_start_time = time(nullptr);
        int err;
        do
        {
            err = SSL_accept(ssl);
            if (err <= 0)
            {
                int ssl_err = SSL_get_error(ssl, err);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
                {
                    // Check for timeout
                    if (time(nullptr) - ssl_start_time > timeout_seconds)
                    {
                        SSL_free(ssl);
                        ssl = nullptr;
                        close(sd);
                        sd = -1;
                        std::cerr << "[SecureTCPServer] SSL handshake timeout" << std::endl;
                        return false;
                    }

                    // Wait for socket to be ready
                    fd_set read_fds, write_fds;
                    FD_ZERO(&read_fds);
                    FD_ZERO(&write_fds);

                    if (ssl_err == SSL_ERROR_WANT_READ)
                    {
                        FD_SET(sd, &read_fds);
                    }
                    else // SSL_ERROR_WANT_WRITE
                    {
                        FD_SET(sd, &write_fds);
                    }

                    struct timeval select_timeout;
                    select_timeout.tv_sec = 1; // 1 second select timeout
                    select_timeout.tv_usec = 0;

                    int select_result = select(sd + 1, &read_fds, &write_fds, nullptr, &select_timeout);
                    if (select_result < 0)
                    {
                        SSL_free(ssl);
                        ssl = nullptr;
                        close(sd);
                        sd = -1;
                        std::cerr << "[SecureTCPServer] Select failed during SSL handshake: " << strerror(errno)
                                  << std::endl;
                        return false;
                    }
                    continue;
                }
                else
                {
                    // Real SSL error
                    SSL_free(ssl);
                    ssl = nullptr;
                    close(sd);
                    sd = -1;
                    std::cerr << "[SecureTCPServer] SSL handshake failed: " << getSSLError(ssl_err) << std::endl;
                    return false;
                }
            }
        } while (err <= 0);
    }

    logConnectionDetails();
    return true;
}

int SecureTCPServer::send(const char *data, size_t size)
{
    if (!ssl)
    {
        std::cerr << "[SecureTCPServer] Not connected" << std::endl;
        return -1;
    }
    if (size == 0)
    {
        return 0;
    }
    time_t start_time = time(nullptr);
    const int timeout_seconds = 10; // 10 second timeout
    int sent;
    do
    {
        sent = SSL_write(ssl, data, size);
        if (sent > 0)
        {
            // Success
            return sent;
        }
        int ssl_err = SSL_get_error(ssl, sent);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
        {
            // Check for timeout
            if (time(nullptr) - start_time > timeout_seconds)
            {
                std::cerr << "[SecureTCPServer] Send timeout" << std::endl;
                return -1;
            }
            // Wait for socket to be ready
            fd_set read_fds, write_fds;
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            if (ssl_err == SSL_ERROR_WANT_READ)
            {
                FD_SET(sd, &read_fds);
            }
            else // SSL_ERROR_WANT_WRITE
            {
                FD_SET(sd, &write_fds);
            }
            struct timeval select_timeout;
            select_timeout.tv_sec = 1; // 1 second select timeout
            select_timeout.tv_usec = 0;
            int select_result = select(sd + 1, &read_fds, &write_fds, nullptr, &select_timeout);
            if (select_result < 0)
            {
                std::cerr << "[SecureTCPServer] Select failed during send: " << strerror(errno) << std::endl;
                return -1;
            }
            // Continue the loop to retry SSL_write
            continue;
        }
        else if (ssl_err == SSL_ERROR_ZERO_RETURN)
        {
            // Connection closed cleanly
            std::cerr << "[SecureTCPServer] Connection closed by peer during send" << std::endl;
            return 0;
        }
        else
        {
            // Real error
            std::cerr << "[SecureTCPServer] Send failed: " + getSSLError(ssl_err) << std::endl;
            return -1;
        }
    } while (true);
}

int SecureTCPServer::recv(char *buf, size_t size)
{
    if (!ssl)
    {
        std::cerr << "[SecureTCPServer] Not connected" << std::endl;
        return -1;
    }
    if (size == 0)
    {
        return 0;
    }
    time_t start_time = time(nullptr);
    const int timeout_seconds = 10; // 10 second timeout
    int received;
    do
    {
        received = SSL_read(ssl, buf, size - 1); // Leave space for null terminator
        if (received > 0)
        {
            // Success
            buf[received] = '\0'; // Null terminate
            return received;
        }
        int ssl_err = SSL_get_error(ssl, received);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
        {
            // Check for timeout
            if (time(nullptr) - start_time > timeout_seconds)
            {
                std::cerr << "[SecureTCPServer] Receive timeout" << std::endl;
                return -1;
            }
            // Wait for socket to be ready
            fd_set read_fds, write_fds;
            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);
            if (ssl_err == SSL_ERROR_WANT_READ)
            {
                FD_SET(sd, &read_fds);
            }
            else // SSL_ERROR_WANT_WRITE
            {
                FD_SET(sd, &write_fds);
            }
            struct timeval select_timeout;
            select_timeout.tv_sec = 1; // 1 second select timeout
            select_timeout.tv_usec = 0;
            int select_result = select(sd + 1, &read_fds, &write_fds, nullptr, &select_timeout);
            if (select_result < 0)
            {
                std::cerr << "[SecureTCPServer] Select failed during recv: " << strerror(errno) << std::endl;
                return -1;
            }
            // Continue the loop to retry SSL_read
            continue;
        }
        else if (ssl_err == SSL_ERROR_ZERO_RETURN)
        {
            // Connection closed cleanly
            return 0; // EOF
        }
        else
        {
            // Real error
            std::cerr << "[SecureTCPServer] Receive failed: " + getSSLError(ssl_err) << std::endl;
            return -1;
        }
    } while (true);
}

int SecureTCPServer::sendNonBlocking(const char *data, const size_t size)
{
    if (!ssl)
    {
        std::cerr << "[SecureTCPServer] Not connected" << std::endl;
        return -1;
    }
    if (size == 0)
    {
        return 0;
    }
    int sent = SSL_write(ssl, data, size);
    if (sent > 0)
    {
        return sent;
    }
    int ssl_err = SSL_get_error(ssl, sent);
    if (ssl_err == SSL_ERROR_WANT_READ)
    {
        errno = EAGAIN; // Indicate would block, need to wait for read
        return -2;      // Special return code meaning "would block on read"
    }
    else if (ssl_err == SSL_ERROR_WANT_WRITE)
    {
        errno = EAGAIN; // Indicate would block, need to wait for write
        return -3;      // Special return code meaning "would block on write"
    }
    else if (ssl_err == SSL_ERROR_ZERO_RETURN)
    {
        return 0; // Connection closed
    }
    else
    {
        std::cerr << "[SecureTCPServer] Send failed: " + getSSLError(ssl_err) << std::endl;
        return -1; // Real error
    }
}

int SecureTCPServer::recvNonBlocking(char *buf, const size_t size)
{
    if (!ssl)
    {
        std::cerr << "[SecureTCPServer] Not connected" << std::endl;
        return -1;
    }
    if (size == 0)
    {
        return 0;
    }
    int received = SSL_read(ssl, buf, size - 1);
    if (received > 0)
    {
        buf[received] = '\0';
        return received;
    }
    int ssl_err = SSL_get_error(ssl, received);
    if (ssl_err == SSL_ERROR_WANT_READ)
    {
        errno = EAGAIN; // Indicate would block, need to wait for read
        return -2;      // Special return code meaning "would block on read"
    }
    else if (ssl_err == SSL_ERROR_WANT_WRITE)
    {
        errno = EAGAIN; // Indicate would block, need to wait for write
        return -3;      // Special return code meaning "would block on write"
    }
    else if (ssl_err == SSL_ERROR_ZERO_RETURN)
    {
        return 0; // Connection closed (EOF)
    }
    else
    {
        std::cerr << "[SecureTCPServer] Receive failed: " + getSSLError(ssl_err) << std::endl;
        return -1; // Real error
    }
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
