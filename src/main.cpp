#include <iostream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <termios.h>
#endif


#include "server.hpp"

void cin_echo(bool echo) {
    #ifdef _WIN32
    HANDLE handle = GetStdHandle(STD_INPUT_HANDLE);

    DWORD mode;
    if(GetConsoleMode(handle, &mode))
            SetConsoleMode(handle,
                echo ? mode | ENABLE_ECHO_INPUT : mode & ~ENABLE_ECHO_INPUT);
    #else
    termios term;
    if(!tcgetattr(STDIN_FILENO, &term)) {
        term.c_lflag = echo ? term.c_lflag | ECHO : term.c_lflag & ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &term);
    }
    #endif
}

int main(int argc, char* argv[]) {
    // Incorrect program arguments
    if(argc != 2) {
        std::cout << "Usage: passman <port>" << std::endl
            << "    <port>: integer in the range [0, 65535]" << std::endl;
        return 1;
    }

    // Try parsing the port number
    std::uint16_t port;
    try {
        const int port_arg = std::stoi(argv[1]);

        if(port_arg < 0 || port_arg > UINT16_MAX)
            throw std::exception();

        port = port_arg;
    } catch(...) {
        std::cout << "\"" << argv[1] << "\" is not a valid port number"
            << std::endl;
        return 2;
    }

    // Get password
    cin_echo(false);

    std::string password;
    std::cout << "Enter password: ";
    std::getline(std::cin, password);
    
    // Clear password line
    std::cout << "\r               \r";
    std::cout.flush();

    cin_echo(true);

    // Trim password
    std::string_view password_view(password);
    const auto password_start = password_view.find_first_not_of(' ');
    if(password_start == std::string::npos)
        password_view = "none";
    else {
        password_view.remove_prefix(password_start);
        const auto password_end = password_view.find_last_not_of(' ');
        password_view.remove_suffix(password_view.size() - password_end - 1);
    }

    // Create the server
    try {
        passman::server server(port, password_view);

        // Run the server in a separate thread
        std::thread server_thread([&server]() {
            server.run();
        });

        std::cout << "Started server on port " << port << std::endl;

        // Handle console commands
        while(true) {
            // Read input from cin
            std::string input;
            std::getline(std::cin, input);

            if(input.empty()) continue;

            // Process commands
            if(input == "stop") {
                std::cout << "Stopping server" << std::endl;

                server.stop();
                server.save_store();
                break;
            } else
                std::cout << "Unknown command" << std::endl;
        }

        // Let the server finish up its work
        server_thread.join();
    } catch(const passman::bad_password&) {
        std::cout << "Password incorrect" << std::endl;
        return 3;
    }

    return 0;
}
