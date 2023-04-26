cmake_minimum_required(VERSION 3.14)
project(ip_proxy)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(client)
add_subdirectory(endpoint-server)
