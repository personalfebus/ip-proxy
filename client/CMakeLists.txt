cmake_minimum_required(VERSION 3.14)
project(proxy)

set(CMAKE_CXX_STANDARD 14)
add_executable(proxy main.cpp)

find_library(NFQUEUE libnetfilter_queue.so)
message(${NFQUEUE})
find_library(CRYPTO_LIB libcryptopp.so)
message(${CRYPTO_LIB})
target_link_libraries(proxy ${NFQUEUE} ${CRYPTO_LIB})
