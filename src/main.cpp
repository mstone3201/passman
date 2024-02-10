#include <iostream>

#include "server.hpp"

int main(int argc, char* argv[]) {
    // Incorrect program arguments
    if(argc != 2) {
        std::cout << "usage: passman <port>" << std::endl
            << "    <port>: integer in the range [0, 65535]" << std::endl;
        return 1;
    }

    // Try parsing the port number
    std::uint16_t port;
    try {
        const int port_arg = std::stoi(argv[1]);

        if(port_arg < 0 || port_arg > UINT16_MAX)
            throw std::exception();

        port = port_arg;
    } catch(...) {
        std::cout << "\"" << argv[1] << "\" is not a valid port number"
            << std::endl;
        return 2;
    }

    // Create the server
    passman::server server(port);
    
    // Run the server in a separate thread
    std::thread server_thread([&server]() {
        server.run();
    });

    std::cout << "Started server on port " << port << std::endl;

    // Handle console commands
    while(true) {
        // Read input from cin
        std::string input;
        std::getline(std::cin, input);

        if(input.empty()) continue;

        // Process commands
        if(input == "stop") {
            std::cout << "Stopping server" << std::endl;

            server.stop();
            break;
        } else
            std::cout << "Unknown command" << std::endl;
    }

    // Let the server finish up its work
    server_thread.join();

    return 0;
}
