# Project setup
cmake_minimum_required(VERSION 3.28)

project(passman)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Read web files
file(READ web/index.html WEB_INDEX_HTML)
string(REPLACE "\n" "" WEB_INDEX_HTML ${WEB_INDEX_HTML})

configure_file(configure/web.hpp include/web.hpp ESCAPE_QUOTES)

# Dependencies
find_package(OpenSSL REQUIRED)
find_package(asio REQUIRED)

# Source files
add_executable(passman src/main.cpp src/server.cpp src/connection.cpp)

# Link and include
target_link_libraries(passman PRIVATE OpenSSL::SSL OpenSSL::Crypto  asio::asio)
target_include_directories(passman PRIVATE include
    ${PROJECT_BINARY_DIR}/include)
