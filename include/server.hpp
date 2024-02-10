#pragma once

#include <cstdint>

#include "include_asio.hpp"

namespace passman {
    class server {
    public:
        explicit server(std::uint16_t port);
        server(const server&) = delete;

        server& operator=(const server&) = delete;

        void run();
        
    private:
        void accept();

        asio::io_context io_context;
        asio::ip::tcp::acceptor acceptor;
    };
}
