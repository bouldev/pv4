cmake_minimum_required(VERSION 3.14)

project(pv4-products)

add_library(pv4-products_private INTERFACE)
target_include_directories(pv4-products_private INTERFACE ${PROJECT_SOURCE_DIR})

add_library(pv4-products SHARED products.cpp)
target_link_libraries(pv4-products pv4-framework)