cmake_minimum_required(VERSION 3.28)

project(passman)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)
find_package(asio REQUIRED)

add_executable(passman
    src/main.cpp
    src/server.cpp
    src/connection.cpp
)

target_link_libraries(passman
    PRIVATE OpenSSL::SSL OpenSSL::Crypto 
    PRIVATE asio::asio
)
target_include_directories(passman PRIVATE include)
