#pragma once

#include <string>
#include <fstream>
#include <unordered_map>

#include "include_asio.hpp"

namespace passman {
    extern const std::string STORE_FILENAME;
    extern const std::string AUTH_LOG_FILENAME;
    extern const std::string BAN_LOG_FILENAME;

    class bad_password : public std::exception {};

    class server {
    public:
        explicit server(std::uint16_t port, std::string_view password);
        server(const server&) = delete;

        server& operator=(const server&) = delete;

        void run();
        void stop();

        void set_store(std::string&& value);
        void save_store() const;

        void auth_fail(const asio::ip::tcp::endpoint&);
        bool is_locked() const;
        void unlock(const asio::ip::tcp::endpoint&);
        
    private:
        asio::awaitable<void> listen();

        const std::string password;

        asio::io_context io_context;
        asio::ssl::context ssl_context;
        asio::ip::tcp::acceptor acceptor;

        std::string store;
        std::string store_hash;
        asio::steady_timer save_timer;
        bool save_scheduled;

        std::uint64_t fail_count;
        std::chrono::system_clock::time_point fail_time;
        std::uint8_t lock_fail_count;
        std::chrono::system_clock::time_point lock_time;
        std::unordered_map<asio::ip::address, std::uint8_t> ban_fail_count;
        std::ofstream auth_log_file;
        std::ofstream ban_log_file;

        friend class connection;
    };
}
