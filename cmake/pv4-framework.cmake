set(FMT_TEST OFF CACHE BOOL "")
add_subdirectory(fmt)

set(JSONCPP_WITH_TESTS OFF CACHE BOOL "")
set(JSONCPP_WITH_POST_BUILD_UNITTEST OFF CACHE BOOL "")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "")
set(BUILD_OBJECT_LIBS OFF CACHE BOOL "")
add_subdirectory(jsoncpp)

set(BSONCXX_POLY_USE_STD ON CACHE BOOL "")
add_subdirectory(mongodb/mongo-cxx-driver)

set(SPDLOG_FMT_EXTERNAL ON CACHE BOOL "")
set(SPDLOG_NO_THREAD_ID ON CACHE BOOL "")
add_subdirectory(spdlog)

add_subdirectory(cpp-httplib)

add_definitions(-DSPDLOG_FMT_EXTERNAL -DSPDLOG_NO_THREAD_ID -DSPDLOG_COMPILED_LIB -DSPDLOG_FUNCTION=__PRETTY_FUNCTION__)
add_library(pv4-framework INTERFACE)

target_include_directories(pv4-framework INTERFACE
	${pv4_SOURCE_DIR}
	${FMT_SOURCE_DIR}/include
	${jsoncpp_SOURCE_DIR}/include
	${MONGOCXX_SOURCE_DIR}/..
	${MONGOCXX_BINARY_DIR}/..
	${spdlog_SOURCE_DIR}/include
	${httplib_SOURCE_DIR}
)