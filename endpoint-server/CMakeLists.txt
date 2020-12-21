cmake_minimum_required(VERSION 3.14)
project(server)

set(CMAKE_CXX_STANDARD 14)
add_executable(server main.cpp)

find_library(NFQUEUE libnetfilter_queue.so)
message(${NFQUEUE})
target_link_libraries(server ${NFQUEUE})
