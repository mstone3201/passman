#include "server.hpp"

#include <iostream>
#include <filesystem>

#include "connection.hpp"
#include "crypto.hpp"

namespace passman {
    constexpr std::uint8_t LOCK_FAIL_COUNT = 5;
    constexpr std::uint8_t BAN_FAIL_COUNT = 25;

    const std::string STORE_FILENAME = "store";
    const std::string AUTH_LOG_FILENAME = "auth.log";
    const std::string BAN_LOG_FILENAME = "ban.log";

    server::server(std::uint16_t port, std::string_view password) :
        password(password),
        io_context(1),
        ssl_context(asio::ssl::context::method::tlsv13_server),
        acceptor(io_context,
            asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)),
        save_timer(io_context),
        save_scheduled(false),
        fail_count(0),
        lock_fail_count(0),
        auth_log_file(AUTH_LOG_FILENAME, std::ios::app),
        ban_log_file(BAN_LOG_FILENAME, std::ios::app)
    {
        ssl_context.set_options(asio::ssl::context::default_workarounds
            | asio::ssl::context::single_dh_use);
        ssl_context.set_password_callback(
            [this](std::size_t max_length,
                asio::ssl::context::password_purpose purpose)
            {
                return server::password;
            }
        );

        // If crypto files don't exist, create them
        if(!std::filesystem::exists(crypto::PRIVATE_KEY_FILENAME)
            || !std::filesystem::exists(crypto::CERTIFICATE_FILENAME))
        {
            std::cout << "Generating RSA keypair and certificate..."
                << std::endl;
            crypto::generate_certificate("passman", server::password);
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

        // Load the store
        {
            std::ifstream file(STORE_FILENAME,
                std::ios::binary | std::ios::ate);
            if(file.is_open()) {
                const std::ifstream::pos_type size = file.tellg();
                file.seekg(0);
                store.resize(size);
                file.read(store.data(), size);
            }
        }
        store_hash = std::move(crypto::base64_encode(crypto::hash(store)));

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

    void server::set_store(std::string&& value) {
        store = std::move(value);
        store_hash = std::move(crypto::base64_encode(crypto::hash(store)));

        if(!save_scheduled) {
            save_scheduled = true;

            save_timer.expires_after(std::chrono::minutes(5));
            save_timer.async_wait([this](const asio::error_code& error) {
                if(!error) {
                    save_scheduled = false;

                    save_store();
                }
            });
        }
    }

    void server::save_store() const {
        std::ofstream file(STORE_FILENAME, std::ios::binary);
        file.write(store.data(), store.size());
    }

    asio::awaitable<void> server::listen() {
        while(true) {
            try {
                asio::ip::tcp::socket socket =
                    co_await acceptor.async_accept(asio::use_awaitable);

                if(ban_fail_count[socket.remote_endpoint().address()] >=
                    BAN_FAIL_COUNT)
                {
                    continue;
                }

                // This connection will be destroyed automatically when its
                // coroutines finish
                connection::create(*this,
                    asio::ssl::stream<asio::ip::tcp::socket>(std::move(socket),
                        ssl_context));
            } catch(...) {}
        }
    }

    void server::auth_fail(const asio::ip::tcp::endpoint& endpoint) {
        // If server is already locked, don't do anything
        if(is_locked())
            return;

        // Record failed authentication
        if(fail_count < std::numeric_limits<std::uint64_t>::max())
            ++fail_count;
        
        fail_time = std::chrono::system_clock::now();

        // Lock the server after LOCK_FAIL_COUNT fails
        if(++lock_fail_count == LOCK_FAIL_COUNT) {
            lock_fail_count = 0;

            lock_time = fail_time + std::chrono::minutes(5);
        }

        // Increment this endpoint's fail count
        std::uint8_t& ban_fails = ban_fail_count[endpoint.address()];
        if(ban_fails < std::numeric_limits<std::uint8_t>::max())
            ++ban_fails;

        // Log failure
        const auto local_time = std::chrono::system_clock::to_time_t(fail_time);
        if(auth_log_file.is_open()) {
            auth_log_file << '['
                << std::put_time(std::localtime(&local_time), "%c")
                << "] " << endpoint << std::endl;
            auth_log_file.flush();
        }

        // Log ban
        if(ban_log_file.is_open() && ban_fails == BAN_FAIL_COUNT) {
            ban_log_file << '['
                << std::put_time(std::localtime(&local_time), "%c")
                << "] " << endpoint.address() << std::endl;
            ban_log_file.flush();
        }
    }

    bool server::is_locked() const {
        return std::chrono::system_clock::now() <= lock_time;
    }

    void server::unlock(const asio::ip::tcp::endpoint& endpoint) {
        lock_fail_count = 0;

        lock_time = std::chrono::system_clock::time_point();

        ban_fail_count[endpoint.address()] = 0;
    }
}
