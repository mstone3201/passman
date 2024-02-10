#include "server.hpp"

// TODO: remove debug print statements
#include <iostream>

namespace passman {
    server::server(std::uint16_t port) :
        acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port))
    {
        accept();
    }

    void server::run() {
        // Run all async operations and wait for them to finish
        // At minimum we are always waiting to accept a new connection
        io_context.run();
    }

    void server::accept() {
        acceptor.async_accept(
            [this](const asio::error_code& error, asio::ip::tcp::socket socket) {
                if(!error) {
                    std::cout << "Connection" << std::endl;
                    
                    // TODO: cleanup
                    new connection(std::move(socket));
                }

                // Wait for the next connection
                accept();
            }
        );
    }
}