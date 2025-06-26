#include "securesockets/SecureTCPServer.hpp"
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <thread>

volatile bool running = true;

void signalHandler(int signal)
{
    std::cout << "\n[Server] Received signal " << signal << ", shutting down gracefully..." << std::endl;
    running = false;
}

int main(void)
{
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    sck::SecureTCPServer server("cert/server.crt", "cert/server.key");
    const int accept_timeout = 5; // seconds

    if (!server.listen(8000))
    {
        std::cerr << "[Server] Failed to listen on port 8000" << std::endl;
        return 1;
    }

    std::cout << "[Server] Listening on port 8000 (non-blocking)..." << std::endl;
    std::cout << "[Server] Waiting for connections... (Press Ctrl+C to stop)" << std::endl;

    while (running)
    {
        // Non-blocking accept with timeout
        if (server.accept(accept_timeout))
        {
            std::cout << "[Server] Connection accepted" << std::endl;

            // Non-blocking receive with timeout
            char buf[4096];
            memset(buf, 0, sizeof(buf));
            auto start = std::chrono::steady_clock::now();
            bool received = false;
            const int recv_timeout = 10; // seconds

            while (!received && running &&
                   std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count() <
                       recv_timeout)
            {
                int bytes_received = server.recv(buf, sizeof(buf));

                if (bytes_received > 0)
                {
                    std::cout << "[Server] Received " << bytes_received << " bytes: " << buf << std::endl;
                    received = true;
                }
                else if (bytes_received == 0)
                {
                    std::cout << "[Server] Client disconnected" << std::endl;
                    break;
                }
                else
                {
                    // No data available yet
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            }

            if (!received)
            {
                std::cerr << "[Server] No data received within timeout" << std::endl;
                continue;
            }

            // Send response
            std::string response = "Server Hello!";
            int attempts = 0;
            const int max_attempts = 5;
            bool response_sent = false;

            while (!response_sent && attempts < max_attempts && running)
            {
                int sent = server.send(response.data(), response.size());

                if (sent > 0)
                {
                    std::cout << "[Server] Sent " << sent << " bytes: " << response << std::endl;
                    response_sent = true;
                }
                else if (sent == 0)
                {
                    std::cout << "[Server] Connection closed during send" << std::endl;
                    break;
                }
                else
                {
                    std::cerr << "[Server] Failed to send response (attempt " << attempts + 1 << ")" << std::endl;
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    attempts++;
                }
            }

            if (!response_sent)
            {
                std::cerr << "[Server] Failed to send response after " << max_attempts << " attempts" << std::endl;
            }

            std::cout << "[Server] Connection handling completed" << std::endl;
        }
        else if (running)
        {
            // No connection available, but server is still running
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    std::cout << "[Server] Server shutdown complete" << std::endl;
    return 0;
}