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
        std::shared_ptr<connection> conn(
            std::make_shared<wrapper>(std::move(socket))
        );
        // Start read/write callback chain
        // When these callbacks end, all shared_ptr references will be out of
        // scope and this connection will be destroyed
        conn->read_request();

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

    void connection::read_request() {
        std::shared_ptr<connection> extend_lifetime(shared_from_this());
        // TODO: not safe, need to handle incorrect requests
        asio::async_read_until(socket, asio::dynamic_buffer(buffer), HTTP_DELIM,
            [this, extend_lifetime](
                const asio::error_code& error,
                std::size_t size
            ) {
                if(!error) {
                    // Request read, now write a response
                    std::cout << "Request received" << std::endl;
                    std::cout << buffer << std::endl;

                    write_response();
                }
            }
        );
    }

    void connection::write_response() {
        std::shared_ptr<connection> extend_lifetime(shared_from_this());
        asio::async_write(socket, asio::buffer(TEST_RESPONSE),
            [this, extend_lifetime](
                const asio::error_code& error,
                std::size_t size
            ) {
                if(!error) {
                    // Response sent, now close socket
                    std::cout << "Response sent" << std::endl;
                    
                    socket.shutdown(asio::ip::tcp::socket::shutdown_both);
                }
            }
        );
    }
}
