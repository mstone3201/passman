# Project setup
cmake_minimum_required(VERSION 3.28)

project(passman)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

# Read web files
set(WEB_FILES "web/index.html" "web/index.js")

foreach(WEB_FILE ${WEB_FILES})
    string(REGEX REPLACE "[/.]" "_" WEB_VAR "${WEB_FILE}")
    string(TOUPPER "${WEB_VAR}" WEB_VAR)

    file(READ "${WEB_FILE}" WEB_CONTENTS)
    # Remove comments
    string(REGEX REPLACE "//[^\n]*|/\\*[^*]*\\*/" "" WEB_CONTENTS
        "${WEB_CONTENTS}")
    # Escape special sequences
    string(REPLACE "\\" "\\\\" WEB_CONTENTS "${WEB_CONTENTS}")
    string(REPLACE "\"" "\\\"" WEB_CONTENTS "${WEB_CONTENTS}")
    # Each line is its own string literal to avoid size constraints
    string(REPLACE "\n" "\"\"" WEB_CONTENTS "${WEB_CONTENTS}")

    set(${WEB_VAR} "${WEB_CONTENTS}")
endforeach()

configure_file(configure/web.hpp include/web.hpp @ONLY)

# Dependencies
find_package(OpenSSL REQUIRED)
find_package(asio REQUIRED)

# Source files
add_executable(passman src/main.cpp src/server.cpp src/connection.cpp
    src/crypto.cpp)

# Link and include
target_link_libraries(passman PRIVATE OpenSSL::SSL OpenSSL::Crypto  asio::asio)
target_include_directories(passman PRIVATE include
    ${PROJECT_BINARY_DIR}/include)
