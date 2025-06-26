#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

#include "securesockets/SecureTCPClient.hpp"

#define NUM_CLIENTS 5
#define CONNECT_TIMEOUT 5   // seconds
#define OPERATION_TIMEOUT 3 // seconds
#define MAX_RETRIES 3

int main(void)
{
    std::vector<std::unique_ptr<sck::SecureTCPClient>> clients;

    std::cout << "Starting " << NUM_CLIENTS << " secure TCP clients (non-blocking)..." << std::endl;

    for (int i = 0; i < NUM_CLIENTS; ++i)
    {
        try
        {
            // Create client
            clients.push_back(std::make_unique<sck::SecureTCPClient>("cert/ca.crt"));
            sck::SecureTCPClient &client = *clients.back();

            std::cout << "[Client " << (i + 1) << "] Attempting to connect (timeout: " << CONNECT_TIMEOUT << "s)..."
                      << std::endl;

            // Non-blocking connect with timeout
            auto connect_start = std::chrono::steady_clock::now();
            bool connected = false;
            int connect_attempts = 0;

            while (!connected &&
                   std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - connect_start)
                           .count() < CONNECT_TIMEOUT)
            {
                if (client.connect("127.0.0.1", 8000, 1)) // 1 second connect attempt
                {
                    connected = true;
                    std::cout << "[Client " << (i + 1) << "] Connected successfully!" << std::endl;
                }
                else if (++connect_attempts >= MAX_RETRIES)
                {
                    break;
                }
                else
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }
            }

            if (!connected)
            {
                std::cerr << "[Client " << (i + 1) << "] Failed to connect after " << connect_attempts << " attempts."
                          << std::endl;
                clients.pop_back();
                continue;
            }

            // Initialize buffer
            char buf[4096];
            memset(buf, 0, sizeof(buf));

            // Send data to server with retries
            std::string message = "Client Hello " + std::to_string(i + 1) + "!";
            auto send_start = std::chrono::steady_clock::now();
            int send_attempts = 0;
            bool message_sent = false;

            while (!message_sent &&
                   std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - send_start)
                           .count() < OPERATION_TIMEOUT)
            {
                int sent = client.send(message.data(), message.size());

                if (sent > 0)
                {
                    std::cout << "[Client " << (i + 1) << "] Sent " << sent << " bytes: " << message << std::endl;
                    message_sent = true;
                }
                else if (sent == 0)
                {
                    std::cerr << "[Client " << (i + 1) << "] Connection closed during send." << std::endl;
                    break;
                }
                else if (++send_attempts >= MAX_RETRIES)
                {
                    break;
                }
                else
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }
            }

            if (!message_sent)
            {
                std::cerr << "[Client " << (i + 1) << "] Failed to send message after " << send_attempts << " attempts."
                          << std::endl;
                continue;
            }

            // Receive data from server with timeout
            auto recv_start = std::chrono::steady_clock::now();
            bool response_received = false;
            int recv_attempts = 0;

            while (!response_received &&
                   std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - recv_start)
                           .count() < OPERATION_TIMEOUT)
            {
                int received = client.recv(buf, sizeof(buf) - 1); // Leave space for null terminator

                if (received > 0)
                {
                    buf[received] = '\0'; // Ensure null termination
                    std::cout << "[Client " << (i + 1) << "] Received " << received << " bytes: " << buf << std::endl;
                    response_received = true;
                }
                else if (received == 0)
                {
                    std::cout << "[Client " << (i + 1) << "] Server closed connection." << std::endl;
                    break;
                }
                else if (++recv_attempts >= MAX_RETRIES)
                {
                    break;
                }
                else
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }
            }

            if (!response_received)
            {
                std::cerr << "[Client " << (i + 1) << "] No response received after " << recv_attempts << " attempts."
                          << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "[Client " << (i + 1) << "] Exception: " << e.what() << std::endl;
        }
    }

    std::cout << "Successfully completed operations with " << clients.size() << " client connections." << std::endl;

    return 0;
}