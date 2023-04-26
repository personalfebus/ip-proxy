cmake_minimum_required(VERSION 3.14)
project(server)

set(CMAKE_CXX_STANDARD 11)
add_executable(server main.cpp)

find_library(NETFILTER_QUEUE libnetfilter_queue.so)
if (NOT NETFILTER_QUEUE)
    message(FATAL_ERROR "netfilter queue library not found")
endif ()

find_library(CRYPTO_PP libcryptopp.so)
if (NOT CRYPTO_PP)
    message(FATAL_ERROR "crypto++ library not found")
endif ()

target_link_libraries(server ${NETFILTER_QUEUE} ${CRYPTO_PP})
