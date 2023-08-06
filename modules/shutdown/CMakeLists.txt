cmake_minimum_required(VERSION 3.14)

project(pv4-shutdown)

add_library(pv4-shutdown SHARED shutdown.cpp)
target_link_libraries(pv4-shutdown)