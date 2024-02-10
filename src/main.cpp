#include <iostream>

#include "server.hpp"

int main() {
    try {
        // Start up the server and run it
        passman::server server(8000);
        server.run();
    } catch(const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
