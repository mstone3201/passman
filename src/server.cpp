#include "server.hpp"

#include <iostream>
#include <filesystem>

#include "connection.hpp"
#include "crypto.hpp"

namespace passman {
    server::server(std::uint16_t port, const std::string& password) :
        io_context(1),
        ssl_context(asio::ssl::context::method::tlsv13_server),
        acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port))
    {
        ssl_context.set_options(asio::ssl::context::default_workarounds
            | asio::ssl::context::single_dh_use);
        ssl_context.set_password_callback(
            [&password](std::size_t max_length,
                asio::ssl::context::password_purpose purpose)
            {
                return password;
            }
        );

        // If crypto files don't exist, create them
        if(!std::filesystem::exists(crypto::PRIVATE_KEY_FILENAME)
            || !std::filesystem::exists(crypto::CERTIFICATE_FILENAME))
        {
            std::cout << "Generating RSA keypair and certificate..."
                << std::endl;
            crypto::generate_certificate("passman", password);
        }
        if(!std::filesystem::exists(crypto::DH_FILENAME)) {
            std::cout << "Generating DH parameters..." << std::endl;
            crypto::generate_dh_parameters();
        }

        // Use crypto files in ssl_context
        try {
            // File exists, so if this throws, password is incorrect
            ssl_context.use_rsa_private_key_file(crypto::PRIVATE_KEY_FILENAME,
                asio::ssl::context::file_format::pem);
        } catch(...) {
            throw bad_password();
        }
        ssl_context.use_certificate_chain_file(crypto::CERTIFICATE_FILENAME);
        ssl_context.use_tmp_dh_file(crypto::DH_FILENAME);

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
                connection::create(*this,
                    asio::ssl::stream<asio::ip::tcp::socket>(
                        co_await acceptor.async_accept(asio::use_awaitable),
                        ssl_context));
            } catch(...) {}
        }
    }
}
