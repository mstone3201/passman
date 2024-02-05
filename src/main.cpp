#ifdef _WIN32
#include <sdkddkver.h>
#endif

#include <iostream>
#include <string>

#include <openssl/evp.h>
#include <asio.hpp>

int main() {
    // SSL test
    EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, "AES-256-CBC", "provider=default");
    EVP_CIPHER_free(cipher);

    // asio test
    asio::io_context context;
    asio::ip::tcp::acceptor acceptor(context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), asio::ip::port_type(8000)));
    asio::ip::tcp::socket socket(context);
    acceptor.accept(socket);

    asio::streambuf request;
    size_t length = asio::read_until(socket, request, "\r\n\r\n");

    std::string request_str(asio::buffers_begin(request.data()), asio::buffers_end(request.data()));
    std::cout << request_str << std::endl;

    std::string response_str = "HTTP/1.0 200 OK\r\n\r\n<html>Hello world!</html>\r\n\r\n";
    asio::write(socket, asio::buffer(response_str));

    return 0;
}
