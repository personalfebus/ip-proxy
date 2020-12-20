cmake_minimum_required(VERSION 3.14)
project(client)

set(CMAKE_CXX_STANDARD 14)
add_executable(client main.cpp)

find_library(NFQUEUE libnetfilter_queue.so)
message(${NFQUEUE})
target_link_libraries(client ${NFQUEUE})
