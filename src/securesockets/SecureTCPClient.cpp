#include "securesockets/SecureTCPClient.hpp"

using namespace sck;

SecureTCPClient::SecureTCPClient(const std::filesystem::path &ca_cert_path)
    : caCertPath(ca_cert_path), serverAddr("0.0.0.0"), serverPort(0), sd(-1)
{
    nullifyHandles();
    initSSL();
    initRawSocket();
}

SecureTCPClient::~SecureTCPClient()
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
}

bool SecureTCPClient::connect(const std::string &server_addr, const unsigned short int server_port,
                              const long int timeout_seconds)
{
    // Clean up any existing connection first
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

    serverAddr = server_addr;
    serverPort = server_port;

    if (!ctx)
    {
        std::cerr << "[SecureTCPClient] SSL context is null" << std::endl;
        return false;
    }

    /* Create socket connection */
    initRawSocket();
    if (sd < 0)
    {
        std::cerr << "[SecureTCPClient] Failed to create socket" << std::endl;
        return false;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(serverPort);

    if (inet_pton(AF_INET, serverAddr.c_str(), &sa.sin_addr) <= 0)
    {
        close(sd);
        sd = -1;
        throw std::runtime_error("[SecureTCPClient] Invalid address: " + serverAddr);
    }

    // Set the socket to non-blocking mode
    if (fcntl(sd, F_SETFL, O_NONBLOCK) < 0)
    {
        std::cerr << "[SecureTCPClient] Failed to set socket to non-blocking mode" << std::endl;
        close(sd);
        sd = -1;
        return false;
    }

    // Attempt connection
    int connect_result = ::connect(sd, (struct sockaddr *)&sa, sizeof(sa));

    if (connect_result < 0)
    {
        if (errno != EINPROGRESS)
        {
            close(sd);
            sd = -1;
            std::cerr << "[SecureTCPClient] Failed to connect to " + serverAddr + ":" + std::to_string(serverPort) +
                             " - " + strerror(errno)
                      << std::endl;
            return false;
        }

        // Connection is in progress, wait for it to complete
        fd_set write_fds, error_fds;
        FD_ZERO(&write_fds);
        FD_ZERO(&error_fds);
        FD_SET(sd, &write_fds);
        FD_SET(sd, &error_fds);

        struct timeval timeout;
        timeout.tv_sec = timeout_seconds;
        timeout.tv_usec = 0;

        int select_result = select(sd + 1, nullptr, &write_fds, &error_fds, &timeout);

        if (select_result <= 0)
        {
            close(sd);
            sd = -1;
            if (select_result == 0)
            {
                std::cerr << "[SecureTCPClient] Connection timeout" << std::endl;
            }
            else
            {
                std::cerr << "[SecureTCPClient] Select failed: " << strerror(errno) << std::endl;
            }
            return false;
        }

        if (FD_ISSET(sd, &error_fds))
        {
            close(sd);
            sd = -1;
            std::cerr << "[SecureTCPClient] Connection failed" << std::endl;
            return false;
        }

        // Check if connection actually succeeded
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(sd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0)
        {
            close(sd);
            sd = -1;
            std::cerr << "[SecureTCPClient] Connection failed: " << strerror(error) << std::endl;
            return false;
        }
    }

    // TCP connection is established, socket remains in non-blocking mode
    // No need to change socket mode - it stays non-blocking

    /* SSL negotiation in non-blocking mode */
    ssl = SSL_new(ctx);
    if (!ssl)
    {
        close(sd);
        sd = -1;
        std::cerr << "[SecureTCPClient] Failed to create SSL structure: " + getOpenSSLError() << std::endl;
        return false;
    }

    SSL_set_fd(ssl, sd);

    // Non-blocking SSL handshake with timeout
    struct timeval ssl_timeout;
    ssl_timeout.tv_sec = 10; // 10 second timeout for SSL handshake
    ssl_timeout.tv_usec = 0;

    time_t start_time = time(nullptr);
    int err;
    do
    {
        err = SSL_connect(ssl);
        if (err <= 0)
        {
            int ssl_err = SSL_get_error(ssl, err);
            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
            {
                // Check for timeout
                if (time(nullptr) - start_time > 10)
                {
                    SSL_free(ssl);
                    ssl = nullptr;
                    close(sd);
                    sd = -1;
                    std::cerr << "[SecureTCPClient] SSL handshake timeout" << std::endl;
                    return false;
                }

                // Wait for socket to be ready and retry
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
                    std::cerr << "[SecureTCPClient] Select failed during SSL handshake: " << strerror(errno)
                              << std::endl;
                    return false;
                }
                // Continue the loop to retry SSL_connect
                continue;
            }
            else
            {
                // Real SSL error
                SSL_free(ssl);
                ssl = nullptr;
                close(sd);
                sd = -1;
                std::cerr << "[SecureTCPClient] SSL handshake failed: " + getSSLError(ssl_err) << std::endl;
                return false;
            }
        }
    } while (err <= 0);

    logConnectionDetails();
    return true;
}

int SecureTCPClient::send(const char *data, size_t size)
{
    if (!ssl)
    {
        std::cerr << "[SecureTCPClient] Not connected" << std::endl;
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
                std::cerr << "[SecureTCPClient] Send timeout" << std::endl;
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
                std::cerr << "[SecureTCPClient] Select failed during send: " << strerror(errno) << std::endl;
                return -1;
            }
            // Continue the loop to retry SSL_write
            continue;
        }
        else if (ssl_err == SSL_ERROR_ZERO_RETURN)
        {
            // Connection closed cleanly
            std::cerr << "[SecureTCPClient] Connection closed by peer during send" << std::endl;
            return 0;
        }
        else
        {
            // Real error
            std::cerr << "[SecureTCPClient] Send failed: " + getSSLError(ssl_err) << std::endl;
            return -1;
        }
    } while (true);
}

int SecureTCPClient::recv(char *buf, const size_t size)
{
    if (!ssl)
    {
        std::cerr << "[SecureTCPClient] Not connected" << std::endl;
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
                std::cerr << "[SecureTCPClient] Receive timeout" << std::endl;
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
                std::cerr << "[SecureTCPClient] Select failed during recv: " << strerror(errno) << std::endl;
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
            std::cerr << "[SecureTCPClient] Receive failed: " + getSSLError(ssl_err) << std::endl;
            return -1;
        }
    } while (true);
}

int SecureTCPClient::sendNonBlocking(const char *data, const size_t size)
{
    if (!ssl)
    {
        std::cerr << "[SecureTCPClient] Not connected" << std::endl;
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
        std::cerr << "[SecureTCPClient] Send failed: " + getSSLError(ssl_err) << std::endl;
        return -1; // Real error
    }
}

int SecureTCPClient::recvNonBlocking(char *buf, const size_t size)
{
    if (!ssl)
    {
        std::cerr << "[SecureTCPClient] Not connected" << std::endl;
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
        std::cerr << "[SecureTCPClient] Receive failed: " + getSSLError(ssl_err) << std::endl;
        return -1; // Real error
    }
}

int SecureTCPClient::getSocketFD() const
{
    return sd;
}

void SecureTCPClient::nullifyHandles()
{
    ctx = nullptr;
    ssl = nullptr;
    meth = nullptr;
}

void SecureTCPClient::initSSL()
{
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    meth = TLS_client_method();
    ctx = SSL_CTX_new(meth);

    if (!ctx)
    {
        throw std::runtime_error("Failed to create SSL context: " + getOpenSSLError());
    }
}

void SecureTCPClient::initRawSocket()
{
    sd = socket(AF_INET, SOCK_STREAM, 0);
}

void SecureTCPClient::logConnectionDetails()
{
    if (!ssl)
    {
        std::cerr << "[SecureTCPClient] Not connected - cannot log connection details\n";
        return;
    }

    std::cout << "[SecureTCPClient] SSL connection established\n";
    std::cout << "  Protocol: " << SSL_get_version(ssl) << "\n";
    std::cout << "  Cipher: " << SSL_get_cipher(ssl) << "\n";

    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (!server_cert)
    {
        std::cout << "  Server did not present a certificate\n";
        return;
    }

    // Subject information
    char *subject = X509_NAME_oneline(X509_get_subject_name(server_cert), nullptr, 0);
    if (subject)
    {
        std::cout << "  Server Subject: " << subject << "\n";
        OPENSSL_free(subject);
    }

    // Issuer information
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(server_cert), nullptr, 0);
    if (issuer)
    {
        std::cout << "  Issuer: " << issuer << "\n";
        OPENSSL_free(issuer);
    }

    // Fixed validity period printing
    ASN1_TIME *not_before = X509_get_notBefore(server_cert);
    ASN1_TIME *not_after = X509_get_notAfter(server_cert);
    if (not_before && not_after)
    {
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio)
        {
            ASN1_TIME_print(bio, not_before);
            char *from_date = nullptr;
            long from_len = BIO_get_mem_data(bio, &from_date);

            BIO_reset(bio);
            ASN1_TIME_print(bio, not_after);
            char *to_date = nullptr;
            long to_len = BIO_get_mem_data(bio, &to_date);

            if (from_date && to_date)
            {
                std::cout << "  Validity Period: " << std::string(from_date, from_len) << " - "
                          << std::string(to_date, to_len) << "\n";
            }
            BIO_free(bio);
        }
    }

    // SANs and other details remain the same...
    X509_free(server_cert);
}

std::string SecureTCPClient::getOpenSSLError() const
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = nullptr;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    return ret;
}

std::string SecureTCPClient::getSSLError(int err_code) const
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

bool SecureTCPClient::verifyServerCertificate()
{
    if (!ssl)
    {
        throw std::runtime_error("[SecureTCPClient] Not connected");
    }

    // Get the server's certificate
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert)
    {
        throw std::runtime_error("[SecureTCPClient] No certificate presented by server");
    }

    // Verify the certificate chain
    long verifyResult = SSL_get_verify_result(ssl);
    if (verifyResult != X509_V_OK)
    {
        X509_free(cert);
        throw std::runtime_error("[SecureTCPClient] Certificate verification failed: " +
                                 std::string(X509_verify_cert_error_string(verifyResult)));
    }

    // Check certificate expiration
    if (!checkCertificateValidity(cert))
    {
        X509_free(cert);
        throw std::runtime_error("[SecureTCPClient] Certificate validity check failed");
    }

    X509_free(cert);
    return true;
}

bool SecureTCPClient::verifyHostname(X509 *cert)
{
    // First try Subject Alternative Names (SANs)
    STACK_OF(GENERAL_NAME) *sans = (STACK_OF(GENERAL_NAME) *)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (sans)
    {
        int sanCount = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < sanCount; i++)
        {
            const GENERAL_NAME *currentName = sk_GENERAL_NAME_value(sans, i);
            if (currentName->type == GEN_DNS)
            {
                const char *dnsName = (const char *)ASN1_STRING_get0_data(currentName->d.dNSName);
                if (strcmp(dnsName, "localhost") == 0 || strcmp(dnsName, "127.0.0.1") == 0)
                {
                    sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
                    return true;
                }
            }
        }
        sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
    }

    // Fall back to Common Name in Subject
    X509_NAME *subject = X509_get_subject_name(cert);
    if (!subject)
    {
        return false;
    }

    int lastPos = -1;
    lastPos = X509_NAME_get_index_by_NID(subject, NID_commonName, lastPos);
    if (lastPos < 0)
    {
        return false;
    }

    X509_NAME_ENTRY *nameEntry = X509_NAME_get_entry(subject, lastPos);
    if (!nameEntry)
    {
        return false;
    }

    ASN1_STRING *nameData = X509_NAME_ENTRY_get_data(nameEntry);
    if (!nameData)
    {
        return false;
    }

    const char *commonName = (const char *)ASN1_STRING_get0_data(nameData);
    if (!commonName)
    {
        return false;
    }

    return strcmp(commonName, "localhost") == 0 || strcmp(commonName, "127.0.0.1") == 0;
}
bool SecureTCPClient::matchHostname(const std::string &pattern, const std::string &hostname)
{
    // Simple wildcard matching (e.g., *.example.com)
    if (pattern.find("*.") == 0)
    {
        std::string domain = pattern.substr(2);
        size_t dotPos = hostname.find('.');
        if (dotPos != std::string::npos)
        {
            std::string hostDomain = hostname.substr(dotPos + 1);
            return hostDomain == domain;
        }
    }

    // Exact match
    return pattern == hostname;
}

bool SecureTCPClient::checkCertificateValidity(X509 *cert)
{
    if (!cert)
    {
        return false;
    }

    // Check notBefore date
    ASN1_TIME *notBefore = X509_get_notBefore(cert);
    if (X509_cmp_current_time(notBefore) > 0)
    {
        return false; // Certificate not yet valid
    }

    // Check notAfter date
    ASN1_TIME *notAfter = X509_get_notAfter(cert);
    if (X509_cmp_current_time(notAfter) < 0)
    {
        return false; // Certificate expired
    }

    return true;
}