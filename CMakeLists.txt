cmake_minimum_required(VERSION 3.10)
project(NetworkExpr4 C)

set(CMAKE_C_STANDARD 99)
# add_definitions(-DDEBUG)

add_executable(NE4Client tcp_echo_cli.c)

add_executable(NE4Server tcp_echo_srv.c)