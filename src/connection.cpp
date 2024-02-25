#include "connection.hpp"

#include "server.hpp"
#include "http_parse.hpp"
#include "web.hpp"

// TODO: remove debug print statements
#include <iostream>

namespace passman {
    std::shared_ptr<connection> connection::create(passman::server& server,
        asio::ssl::stream<asio::ip::tcp::socket>&& ssl_socket
    ) {
        // Wrap connection so that make_shared can access the constructor and
        // destructor. Here connection::create can see these since it is in the
        // scope of the class, despite them being private.
        struct wrapper : public connection {
            wrapper(passman::server& server,
                asio::ssl::stream<asio::ip::tcp::socket>&& ssl_socket
            ) :
                connection(server, std::move(ssl_socket)) {}
        };

        // Create a wrapper and then let it decay to a connection
        std::shared_ptr<connection> conn(
            std::make_shared<wrapper>(server, std::move(ssl_socket)));
        // Start read/write chain
        // When this coroutine ends, all shared_ptr references will be out of
        // scope and this connection will be destroyed
        asio::co_spawn(server.io_context, conn->handle_request(),
            asio::detached);

        return conn;
    }

    connection::connection(passman::server& server,
        asio::ssl::stream<asio::ip::tcp::socket>&& ssl_socket
    ) :
        server(server),
        ssl_socket(std::move(ssl_socket)),
        timer(server.io_context)
    {
        std::cout << "Connection opened" << std::endl;
        
        // Start timeout timer
        timer.expires_after(std::chrono::seconds(5));
        timer.async_wait([this](const asio::error_code& error) {
            // If the timer is cancelled it runs the handler immediately and is
            // given an operation_aborted error
            if(!error) {
                connection::ssl_socket.next_layer().cancel();
                std::cout << "Connection timed out" << std::endl;
            }
        });
    }

    connection::~connection() {
        std::cout << "Connection closed" << std::endl;
    }

    asio::awaitable<void> connection::handle_request() {
        // This adds a reference to this connection, which keeps it alive at
        // least until this coroutine returns
        std::shared_ptr<connection> extend_lifetime(shared_from_this());

        // Perform SSL handshake
        
        try {
            co_await ssl_socket.async_handshake(
                asio::ssl::stream<asio::ip::tcp::socket>::server,
                asio::use_awaitable);
        } catch(...) {
            co_return;
        }

        // Read request

        http::request http_request;
        // Scope to control the lifetime of parsing objects
        {
            std::array<char, 2048> buffer;
            std::string_view buffer_view;
            http::parser_coroutine parser = http::parse_request(buffer_view,
                http_request, server.password);

            while(true) {
                try {
                    // Read some data into the buffer
                    const std::size_t size =
                        co_await ssl_socket.async_read_some(
                            asio::buffer(buffer), asio::use_awaitable);

                    buffer_view = std::string_view(buffer.data(), size);
                } catch(...) {
                    // If the timer times out, the underlying socket is
                    // cancelled, which throws an error and gets caught here
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

        // Process and validate request
        switch(http_request.resource) {
        case http::resource::INDEX_HTML:
        case http::resource::INDEX_JS:
            if(http_request.method != http::request_method::GET)
                co_return;
            break;
        case http::resource::STORE:
            if(http_request.method == http::request_method::POST)
                // POST requests are always authorized
                server.store = std::move(http_request.body.value_or(""));
            else if(!http_request.authorized)
                // Respond to let the client know they are unauthorized
                http_request.resource = http::resource::INVALID;
            break;
        }

        // Write response

        try {
            co_await asio::async_write(ssl_socket,
                asio::buffer(get_response_str(http_request)),
                asio::use_awaitable);
        } catch(...) {
            co_return;
        }

        // Perform clean shutdown

        try {
            co_await ssl_socket.async_shutdown(asio::use_awaitable);
            ssl_socket.next_layer().shutdown(
                asio::ip::tcp::socket::shutdown_both);
        } catch(...) {
            co_return;
        }

        // Request handled, cancel timeout
        timer.cancel();
    }

    std::string connection::get_response_str(
        const http::request& http_request) const
    {
        // Response line

        std::string response(http::HTTP_VERSION);
        response.push_back(' ');

        if(http_request.resource == http::resource::INVALID)
            response.append(http::HTTP_RESPONSE_INVALID);
        else
            response.append(http::HTTP_RESPONSE_OK);
        response.append(http::HTTP_EOL);

        // Header & Body

        switch(http_request.resource) {
        case http::resource::INVALID:
            response.append("Content-Length: 0").append(http::HTTP_DELIM);
            break;
        case http::resource::INDEX_HTML:
            response.append("Content-Length: ")
                .append(std::to_string(web::INDEX_HTML.size()))
                .append(http::HTTP_DELIM).append(web::INDEX_HTML);
            break;
        case http::resource::INDEX_JS:
            response.append("Content-Length: ")
                .append(std::to_string(web::INDEX_JS.size()))
                .append(http::HTTP_DELIM).append(web::INDEX_JS);
            break;
        case http::resource::STORE:
            if(http_request.method == http::request_method::GET)
                response.append("Content-Length: ")
                    .append(std::to_string(server.store.size()))
                    .append(http::HTTP_DELIM).append(server.store);
            else
                response.append("Content-Length: 0").append(http::HTTP_DELIM);
            break;
        }

        return response;
    }
}
