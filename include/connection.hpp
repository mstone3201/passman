#pragma once

#include "include_asio.hpp"
#include "http.hpp"

namespace passman {
    class server;

    class connection : public std::enable_shared_from_this<connection> {
    public:
        static std::shared_ptr<connection> create(server& server,
            asio::ssl::stream<asio::ip::tcp::socket>&& ssl_socket);

    private:
        explicit connection(server& server,
            asio::ssl::stream<asio::ip::tcp::socket>&& ssl_socket);
        connection(const connection&) = delete;

        ~connection();

        connection& operator=(const connection&) = delete;

        // handle_request() calls shared_from_this(), so it must not be called
        // from within the constructor
        asio::awaitable<void> handle_request();

        std::string get_response_str(const http::request& http_request) const;

        server& server;

        asio::ssl::stream<asio::ip::tcp::socket> ssl_socket;
        asio::steady_timer timer;
    };
}
