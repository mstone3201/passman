#pragma once

#include <string>

#include "include_asio.hpp"

namespace passman {
    class connection {
    public:
        explicit connection(asio::ip::tcp::socket&& socket);
        connection(const connection&) = delete;
        connection& operator=(const connection&) = delete;

    private:
        void read_request();
        void write_response();

        asio::ip::tcp::socket socket;

        std::string buffer;
    };
}
