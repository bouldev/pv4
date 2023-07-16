.PHONY: normal all
.ONESHELL:

normal: libpv4-nemc-helper.so
all: libpv4-nemc-helper.so libpv4-aarch64-nemc-helper.so

libpv4-nemc-helper.so: *.cpp
	g++ --std=c++20 nemc_helper.cpp \
		-I../../mongodb/mongo-cxx-driver/src/ -I../../depends/mongo-cxx-driver/src/ \
		-shared -fPIC -o libpv4-nemc-helper.so

libpv4-aarch64-nemc-helper.so: *.cpp
	aarch64-linux-gnu-g++ -O9 --std=c++20 nemc_helper.cpp \
		-I../../mongodb/mongo-cxx-driver/src/ -I../../depends/mongo-cxx-driver/src/ \
		-shared -fPIC -o libpv4-aarch64-nemc-helper.so
