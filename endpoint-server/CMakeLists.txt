cmake_minimum_required(VERSION 3.14)
project(server)

set(CMAKE_CXX_STANDARD 14)
add_executable(server main.cpp)

find_library(NFQUEUE libnetfilter_queue.so)
message(${NFQUEUE})
find_library(CRYPTO_LIB libcryptopp.so)
message(${CRYPTO_LIB})
target_link_libraries(server ${NFQUEUE} ${CRYPTO_LIB})
