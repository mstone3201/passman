#include "connection.hpp"

// TODO: remove debug print statements
#include <iostream>

constexpr std::string_view HTTP_DELIM("\r\n\r\n");
constexpr std::string_view TEST_RESPONSE("HTTP/1.1 200 OK\r\n\r\n<html>Hello world!<a href=\"/index.html\">here</a></html>\r\n\r\n");

namespace passman {
    connection::connection(asio::ip::tcp::socket&& socket) :
        socket(std::move(socket))
    {
        read_request();
    }

    void connection::read_request() {
        // TODO: not safe, need to handle incorrect requests
        asio::async_read_until(socket, asio::dynamic_buffer(buffer), HTTP_DELIM,
            [this](const asio::error_code& error, std::size_t size) {
                if(!error) {
                    // Request read, now write a response
                    std::cout << "Request received" << std::endl;
                    std::cout << buffer << std::endl;

                    write_response();
                } else if(error != asio::error::operation_aborted)
                    // Socket still open
                    socket.close();
            }
        );
    }

    void connection::write_response() {
        asio::async_write(socket, asio::buffer(TEST_RESPONSE),
            [this](const asio::error_code& error, std::size_t size) {
                if(!error) {
                    // Response sent, now close socket
                    std::cout << "Response sent" << std::endl;
                    
                    socket.shutdown(asio::ip::tcp::socket::shutdown_both);
                }
                
                if(error != asio::error::operation_aborted)
                    // Socket still open
                    socket.close();
            }
        );
    }
}
