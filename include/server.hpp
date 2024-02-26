#pragma once

#include <string>

#include "include_asio.hpp"

namespace passman {
    extern const std::string STORE_FILENAME;

    class bad_password : public std::exception {};

    class server {
    public:
        explicit server(std::uint16_t port, const std::string& password);
        server(const server&) = delete;

        server& operator=(const server&) = delete;

        void run();
        void stop();

        void set_store(std::string&& value);
        void save_store() const;
        
    private:
        asio::awaitable<void> listen();

        const std::string password;

        asio::io_context io_context;
        asio::ssl::context ssl_context;
        asio::ip::tcp::acceptor acceptor;

        std::string store;
        asio::steady_timer save_timer;
        bool save_scheduled;

        friend class connection;
    };
}
