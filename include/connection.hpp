#pragma once

#include "include_asio.hpp"

namespace passman {
    class connection : public std::enable_shared_from_this<connection> {
    public:
        static std::shared_ptr<connection> create(
            asio::ssl::stream<asio::ip::tcp::socket>&& ssl_socket);

    private:
        explicit connection(
            asio::ssl::stream<asio::ip::tcp::socket>&& ssl_socket);
        connection(const connection&) = delete;

        ~connection();

        connection& operator=(const connection&) = delete;

        // handle_request() calls shared_from_this(), so it must not be called
        // from within the constructor
        asio::awaitable<void> handle_request();

        asio::ssl::stream<asio::ip::tcp::socket> ssl_socket;
        asio::steady_timer timer;
    };
}
