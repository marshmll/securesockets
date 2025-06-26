#include "securesockets/SecureTCPClient.hpp"
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

int main(void)
{
    sck::SecureTCPClient client("cert/ca.crt");
    const int timeout_seconds = 10;

    // Non-blocking connect with timeout
    auto start = std::chrono::steady_clock::now();
    bool connected = false;

    while (!connected &&
           std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count() <
               timeout_seconds)
    {
        if (client.connect("127.0.0.1", 8000, 1)) // 1 second connect attempt
        {
            connected = true;
            std::cout << "Successfully connected to server!" << std::endl;
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    if (!connected)
    {
        std::cerr << "Failed to connect to server after " << timeout_seconds << " seconds." << std::endl;
        return 1;
    }

    // Non-blocking send/receive loop
    std::string message = "Client Hello!";
    int attempts = 0;
    const int max_attempts = 5;

    while (attempts < max_attempts)
    {
        // Send data
        int sent = client.send(message.data(), message.size());

        if (sent > 0)
        {
            std::cout << "[Client] Sent " << sent << " bytes: " << message << std::endl;
            break;
        }
        else if (sent == 0)
        {
            std::cerr << "[Client] Connection closed during send" << std::endl;
            return 1;
        }
        else
        {
            std::cerr << "[Client] Failed to send data (attempt " << attempts + 1 << ")" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            attempts++;
        }
    }

    if (attempts >= max_attempts)
    {
        std::cerr << "[Client] Max send attempts reached" << std::endl;
        return 1;
    }

    // Wait for server response with timeout
    std::vector<char> buf(4096);
    start = std::chrono::steady_clock::now();
    bool received_response = false;

    while (!received_response &&
           std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count() <
               timeout_seconds)
    {
        int received = client.recv(buf.data(), buf.size());

        if (received > 0)
        {
            std::cout << "[Client] Received " << received << " bytes: " << buf.data() << std::endl;
            received_response = true;
        }
        else if (received == 0)
        {
            std::cout << "[Client] Connection closed by server" << std::endl;
            break;
        }
        else
        {
            // No data available yet
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    if (!received_response)
    {
        std::cerr << "[Client] No response received within timeout" << std::endl;
        return 1;
    }

    std::cout << "[Client] Communication completed successfully" << std::endl;
    return 0;
}