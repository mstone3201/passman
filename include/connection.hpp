#pragma once

#include <memory>
#include <string>

#include "include_asio.hpp"

namespace passman {
    class connection : public std::enable_shared_from_this<connection> {
    public:
        static std::shared_ptr<connection> create(
            asio::ip::tcp::socket&& socket
        );
    private:
        explicit connection(asio::ip::tcp::socket&& socket);
        connection(const connection&) = delete;

        ~connection();

        connection& operator=(const connection&) = delete;

        void read_request();
        void write_response();

        asio::ip::tcp::socket socket;

        std::string buffer;
    };
}
