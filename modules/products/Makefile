.PHONY: normal all
.ONESHELL:

normal: libpv4-products.so
all: libpv4-products.so libpv4-aarch64-products.so

libpv4-products.so: *.cpp
	g++ --std=c++20 products.cpp \
		-I../../mongodb/mongo-cxx-driver/src/ -I../../depends/mongo-cxx-driver/src/ \
		-rdynamic -I../.. -I../../jsoncpp/include \
		-shared -fPIC -o libpv4-products.so
libpv4-aarch64-products.so: *.cpp
	aarch64-linux-gnu-g++ -O9 --std=c++20 \
		-I../../jsoncpp/include \
		-rdynamic products.cpp -I../../mongodb/mongo-cxx-driver/src/ \
		-I../../depends/mongo-cxx-driver-aarch64/src/ -I../.. \
		-shared -fPIC -o libpv4-aarch64-products.so
