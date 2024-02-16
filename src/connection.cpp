#include "connection.hpp"

#include "http_parse.hpp"
#include "web.hpp"

// TODO: remove debug print statements
#include <iostream>

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
        std::shared_ptr<connection> conn(
            std::make_shared<wrapper>(std::move(socket)));
        // Start read/write chain
        // When this coroutine ends, all shared_ptr references will be out of
        // scope and this connection will be destroyed
        asio::co_spawn(socket.get_executor(), conn->handle_request(),
            asio::detached);

        return conn;
    }

    connection::connection(asio::ip::tcp::socket&& socket) :
        socket(std::move(socket)),
        timer(connection::socket.get_executor())
    {
        std::cout << "Connection opened" << std::endl;
        
        // Start timeout timer
        timer.expires_after(std::chrono::seconds(3));
        timer.async_wait([this](const asio::error_code& error) {
            // If the timer is cancelled it runs the handler immediately and is
            // given an operation_aborted error
            if(!error)
                connection::socket.cancel();
        });
    }

    connection::~connection() {
        std::cout << "Connection closed" << std::endl;
    }

    asio::awaitable<void> connection::handle_request() {
        // This adds a reference to this connection, which keeps it alive at
        // least until this coroutine returns
        std::shared_ptr<connection> extend_lifetime(shared_from_this());

        // Read request

        http::request http_request;
        // Scope to control the lifetime of parsing objects
        {
            std::array<char, 2048> buffer;
            std::string_view buffer_view;
            http::parser_coroutine parser = http::parse_request(buffer_view,
                http_request);

            while(true) {
                try {
                    // Read some data into the buffer
                    const std::size_t size = co_await socket.async_read_some(
                        asio::buffer(buffer), asio::use_awaitable);

                    buffer_view = std::string_view(buffer.data(), size);
                } catch(...) {
                    // If the timer times out, the socket is cancelled, which
                    // throws and error and gets caught here
                    co_return;
                }

                // Try to parse what we have
                switch(parser.parse()) {
                case http::parse_result::VALID:
                    goto read_valid;
                case http::parse_result::INVALID:
                    co_return;
                case http::parse_result::INCOMPLETE:
                    break;
                }
            }

            // Destroy parsing objects
        }
    read_valid:

        // Request fully recieved, cancel the timeout
        timer.cancel();

        std::cout << "Request for \"" << http_request.uri << "\" on thread "
            << std::this_thread::get_id() << std::endl;

        // Write response

        try {
            co_await asio::async_write(socket, asio::buffer(HTTP_INDEX_HTML),
                asio::use_awaitable);
        } catch(...) {
            co_return;
        }

        std::cout << "Response sent on thread " << std::this_thread::get_id()
            << std::endl;

        socket.shutdown(asio::ip::tcp::socket::shutdown_both);
    }
}
