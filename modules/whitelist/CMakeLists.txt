cmake_minimum_required(VERSION 3.14)

project(pv4-whitelist)

option(FBDB_READONLY "Make database readonly" OFF)
if(FBDB_READONLY)
	add_definitions(-DFBDB_READONLY)
endif()

add_library(pv4-whitelist SHARED whitelist.cpp)
target_link_libraries(pv4-whitelist pv4-framework)