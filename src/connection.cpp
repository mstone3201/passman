#include "connection.hpp"

// TODO: remove debug print statements
#include <iostream>

constexpr std::string_view HTTP_DELIM("\r\n\r\n");
constexpr std::string_view TEST_RESPONSE("HTTP/1.1 200 OK\r\n\r\n\
    <html>Hello world! <a href=\"/index.html\">here</a></html>\r\n\r\n");

namespace passman {
    std::shared_ptr<connection> connection::create(
        asio::ip::tcp::socket&& socket
    ) {
        // Wrap connection so that make_shared can access the constructor and
        // destructor. Here connection::create can see these since it is in the
        // scope of the class, despite them being private.
        struct wrapper : public connection {
            wrapper(asio::ip::tcp::socket&& socket) :
                connection(std::move(socket))
            {}
        };

        // Create a wrapper and then let it decay to a connection
        std::shared_ptr<connection> conn(std::make_shared<wrapper>(std::move(socket)));

        // Start read/write chain
        // When this coroutine ends, all shared_ptr references will be out of
        // scope and this connection will be destroyed
        asio::co_spawn(socket.get_executor(), conn->handle_request(), asio::detached);

        return conn;
    }

    connection::connection(asio::ip::tcp::socket&& socket) :
        socket(std::move(socket))
    {
        std::cout << "Connection opened" << std::endl;
    }

    connection::~connection() {
        std::cout << "Connection closed" << std::endl;
    }

    asio::awaitable<void> connection::handle_request() {
        // This adds a reference to this connection, which keeps it alive at
        // least until this coroutine returns
        std::shared_ptr<connection> extend_lifetime(shared_from_this());

        // Read request

        std::string buffer;
        try {
            // TODO: not safe, need to handle incorrect requests
            std::size_t size = co_await asio::async_read_until(socket,
                asio::dynamic_buffer(buffer), HTTP_DELIM, asio::use_awaitable);
        } catch(...) {
            co_return;
        }

        std::cout << "Request received" << std::endl;
        std::cout << buffer << std::endl;

        // Write response

        try {
            co_await asio::async_write(socket, asio::buffer(TEST_RESPONSE),
                asio::use_awaitable);
        } catch(...) {
            co_return;
        }

        std::cout << "Response sent" << std::endl;

        socket.shutdown(asio::ip::tcp::socket::shutdown_both);
    }
}
