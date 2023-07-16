.PHONY: normal all
.ONESHELL:

normal: libpv4-shutdown.so
all: libpv4-shutdown.so libpv4-aarch64-shutdown.so

libpv4-shutdown.so: *.cpp
	g++ --std=c++20 shutdown.cpp \
		-shared -fPIC -o libpv4-shutdown.so
libpv4-aarch64-shutdown.so: *.cpp
	aarch64-linux-gnu-g++ -O9 --std=c++20 -shared \
		shutdown.cpp -fPIC -o libpv4-aarch64-shutdown.so
