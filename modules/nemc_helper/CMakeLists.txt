cmake_minimum_required(VERSION 3.14)

project(pv4-nemc-helper)

add_library(pv4-nemc-helper SHARED nemc_helper.cpp)
target_link_libraries(pv4-nemc-helper pv4-framework)