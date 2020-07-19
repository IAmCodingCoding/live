cmake_minimum_required(VERSION 3.10)
project(live)

set(CMAKE_CXX_STANDARD 11)

add_executable(live main.cpp)

target_link_libraries(live avformat avcodec avutil pthread jrtp)