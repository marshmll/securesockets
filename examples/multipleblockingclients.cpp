#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

#include "securesockets/SecureTCPClient.hpp"

#define NUM_CLIENTS 5

int main(void)
{
    std::vector<std::unique_ptr<sck::SecureTCPClient>> clients;

    std::cout << "Starting " << NUM_CLIENTS << " secure TCP clients..." << std::endl;

    for (int i = 0; i < NUM_CLIENTS; ++i)
    {
        try
        {
            clients.push_back(std::make_unique<sck::SecureTCPClient>("cert/ca.crt"));
            sck::SecureTCPClient &client = *clients.back();

            std::cout << "[Client " << (i + 1) << "] Attempting to connect..." << std::endl;

            if (!client.connect("127.0.0.1", 8000))
            {
                std::cerr << "[Client " << (i + 1) << "] Failed to connect to server." << std::endl;
                clients.pop_back(); // Remove failed client
                continue;
            }

            std::cout << "[Client " << (i + 1) << "] Connected successfully!" << std::endl;

            // Initialize buffer
            char buf[4096];
            memset(buf, 0, sizeof(buf));

            // Send data to server
            std::string message = "Client Hello " + std::to_string(i + 1) + "!";
            int sent = client.send(message.data(), message.size());

            if (sent > 0)
            {
                std::cout << "[Client " << (i + 1) << "] Sent " << sent << " bytes: " << message << std::endl;
            }
            else
            {
                std::cerr << "[Client " << (i + 1) << "] Error sending data." << std::endl;
            }

            // Receive data from server
            int received = client.recv(buf, sizeof(buf) - 1); // Leave space for null terminator

            if (received > 0)
            {
                buf[received] = '\0'; // Ensure null termination
                std::cout << "[Client " << (i + 1) << "] Received " << received << " bytes: " << buf << std::endl;
            }
            else if (received == 0)
            {
                std::cout << "[Client " << (i + 1) << "] Server closed connection." << std::endl;
            }
            else
            {
                std::cerr << "[Client " << (i + 1) << "] Error receiving data." << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "[Client " << (i + 1) << "] Exception: " << e.what() << std::endl;
        }
    }

    std::cout << "Successfully created " << clients.size() << " client connections." << std::endl;

    // Clients will be automatically cleaned up when vector goes out of scope
    return 0;
}