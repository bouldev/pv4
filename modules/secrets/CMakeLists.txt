cmake_minimum_required(VERSION 3.14)

project(pv4-secrets)

add_library(pv4-secrets INTERFACE)
target_include_directories(pv4-secrets INTERFACE ${PROJECT_SOURCE_DIR})