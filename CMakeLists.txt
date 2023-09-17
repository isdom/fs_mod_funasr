cmake_minimum_required(VERSION 3.14)

project(mode_funasr)

set(CMAKE_CXX_STANDARD 14 CACHE STRING "The C++ version to be used.")

include_directories(/usr/local/freeswitch/include/freeswitch)
include_directories(third_party/websocket)
include_directories(third_party/asio/asio/include)
include_directories(third_party/json/include)

ADD_LIBRARY (mod_funasr SHARED mod_funasr.cpp)