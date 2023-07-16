.PHONY: normal all
.ONESHELL:

# What is expected to be pre-installed
# libzstd-dev

normal: libpv4-whitelist.so
all: libpv4-whitelist.so libpv4-aarch64-whitelist.so

libpv4-whitelist.so: *.cpp *.h
	g++ --std=c++20 whitelist.cpp \
		-I../../mongodb/mongo-cxx-driver/src/ -I../../depends/mongo-cxx-driver/src/ \
		-I../../jsoncpp/include -I../../fmt/include -I../../spdlog/include \
		-DSPDLOG_FMT_EXTERNAL -DSPDLOG_NO_THREAD_ID \
		-DSPDLOG_COMPILED_LIB \
		-DSPDLOG_FUNCTION=__PRETTY_FUNCTION__ -rdynamic \
		-I../.. -lssl -lcrypto -lzstd -lresolv -lz \
		-shared -fPIC -o libpv4-whitelist.so
libpv4-aarch64-whitelist.so: *.cpp *.h
	aarch64-linux-gnu-g++ -O9 --std=c++20 -DSPDLOG_FMT_EXTERNAL \
		-DSPDLOG_NO_THREAD_ID -DSPDLOG_FUNCTION=__PRETTY_FUNCTION__ \
		-rdynamic whitelist.cpp -I../../mongodb/mongo-cxx-driver/src/ \
		-I../../depends/mongo-cxx-driver-aarch64/src/ -I../.. \
		-I../../jsoncpp/include -I../../fmt/include -I../../spdlog/include \
		-lssl -lcrypto -lzstd -lresolv -lz -shared -fPIC -o libpv4-aarch64-whitelist.so
