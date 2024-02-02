cmake_minimum_required(VERSION 3.28)

project(passman)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL 3.0 REQUIRED)

add_executable(passman src/main.cpp)

target_link_libraries(passman PRIVATE OpenSSL::SSL OpenSSL::Crypto)
