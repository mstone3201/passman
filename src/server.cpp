#include "server.hpp"

#include "connection.hpp"

namespace passman {
    server::server(std::uint16_t port) :
        io_context(1),
        acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port))
    {
        asio::co_spawn(io_context, listen(), asio::detached);
    }

    void server::run() {
        // Run all async operations and wait for them to finish
        // At minimum listen() will always be running
        io_context.run();
    }

    void server::stop() {
        // Make run() return
        io_context.stop();
    }

    asio::awaitable<void> server::listen() {
        while(true) {
            try {
                // This connection will be destroyed automatically when its
                // coroutines finish
                connection::create(
                    co_await acceptor.async_accept(asio::use_awaitable));
            } catch(...) {}
        }
    }
}
