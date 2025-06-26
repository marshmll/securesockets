#include "securesockets/SecureTCPServer.hpp"
#include <csignal>
#include <cstring>
#include <iostream>
#include <unistd.h>

// Global flag for graceful shutdown
volatile bool running = true;

void signalHandler(int signal)
{
    std::cout << "\n[Server] Received signal " << signal << ", shutting down gracefully..." << std::endl;
    running = false;
}

int main(void)
{
    // Setup signal handling for graceful shutdown
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    sck::SecureTCPServer server("cert/server.crt", "cert/server.key");

    if (!server.listen(8000))
    {
        std::cerr << "[Server] Failed to listen on port 8000" << std::endl;
        return 1;
    }

    std::cout << "[Server] Listening on port 8000..." << std::endl;
    std::cout << "[Server] Waiting for connections... (Press Ctrl+C to stop)" << std::endl;

    while (running)
    {
        if (server.accept())
        {
            std::cout << "[Server] Connection accepted" << std::endl;

            // First, wait for client message (typical server behavior)
            char buf[4096];
            memset(buf, 0, sizeof(buf));

            int received = server.recv(buf, sizeof(buf));

            if (received > 0)
            {
                std::cout << "[Server] Received " << received << " bytes: " << buf << std::endl;

                // Send response back to client
                std::string response = "Server Hello!";
                int sent = server.send(response.data(), response.size());

                if (sent > 0)
                {
                    std::cout << "[Server] Sent " << sent << " bytes: " << response << std::endl;
                }
                else if (sent == 0)
                {
                    std::cout << "[Server] Connection closed during send" << std::endl;
                }
                else
                {
                    std::cerr << "[Server] Failed to send response" << std::endl;
                }
            }
            else if (received == 0)
            {
                std::cout << "[Server] Client disconnected" << std::endl;
            }
            else
            {
                std::cerr << "[Server] Failed to receive data from client" << std::endl;
            }

            std::cout << "[Server] Connection handling completed" << std::endl;
        }
        else
        {
            // No connection available, sleep briefly to avoid busy waiting
            usleep(10000); // 10ms
        }
    }

    std::cout << "[Server] Server shutdown complete" << std::endl;
    return 0;
}