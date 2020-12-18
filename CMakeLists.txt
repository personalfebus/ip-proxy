cmake_minimum_required(VERSION 3.14)
project(ip_proxy)

set(CMAKE_CXX_STANDARD 14)
add_executable(ip_proxy main.cpp)

find_library(NFQUEUE libnetfilter_queue.so)
message(${NFQUEUE})
target_link_libraries(ip_proxy ${NFQUEUE})
