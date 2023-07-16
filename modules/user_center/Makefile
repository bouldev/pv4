.PHONY: normal all
.ONESHELL:

# What is expected to be pre-installed
# libzstd-dev

normal: libpv4-user-center.so
all: libpv4-user-center.so libpv4-aarch64-user-center.so

libpv4-user-center.so: *.cpp
	g++ --std=c++20 user_center.cpp \
		captcha_gen/Captcha.cxx cotp/cotp.c cotp/otpuri.c qrcode/qrcode.c -Icaptcha_gen \
		-I../../mongodb/mongo-cxx-driver/src/ -I../../depends/mongo-cxx-driver/src/ \
		-I../../jsoncpp/include -I../../fmt/include -I../../spdlog/include \
		-DSPDLOG_FMT_EXTERNAL -DSPDLOG_NO_THREAD_ID \
		-DSPDLOG_FUNCTION=__PRETTY_FUNCTION__ -rdynamic \
		-I../.. -lssl -lcrypto -lzstd -lresolv -lz -g \
		-Wno-deprecated-enum-enum-conversion \
		-lopencv_core \
		-shared -fPIC -o libpv4-user-center.so
libpv4-aarch64-user-center.so: *.cpp
	aarch64-linux-gnu-g++ -O9 --std=c++20 -DSPDLOG_FMT_EXTERNAL \
		-DSPDLOG_NO_THREAD_ID -DSPDLOG_FUNCTION=__PRETTY_FUNCTION__ \
		captcha_gen/Captcha.cxx cotp/cotp.c cotp/otpuri.c qrcode/qrcode.c -Icaptcha_gen \
		-rdynamic user_center.cpp -I../../mongodb/mongo-cxx-driver/src/ \
		-I../../depends/mongo-cxx-driver-aarch64/src/ -I../.. \
		-Wno-deprecated-enum-enum-conversion \
		-lopencv_core \
		-I../../jsoncpp/include -I../../fmt/include -I../../spdlog/include \
		-lssl -lcrypto -lzstd -lresolv -lz -shared -fPIC -o libpv4-aarch64-user-center.so
