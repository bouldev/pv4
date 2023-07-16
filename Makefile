.PHONY: normal all
.ONESHELL:

# What is expected to be pre-installed
# libzstd-dev

normal: pv4

depends/libfmt/libfmt.a:
	cd depends
	mkdir -p libfmt&&cd libfmt
	CXXFLAGS="-fPIC -pie" cmake -DCMAKE_VISIBILITY_INLINES_HIDDEN=OFF -DCMAKE_CXX_VISIBILITY_PRESET=default -DFMT_TEST=OFF ../../fmt/
	$(MAKE)
depends/libfmt-aarch64/libfmt.a:
	cd depends
	mkdir -p libfmt-aarch64&&cd libfmt-aarch64
	CXXFLAGS="-fPIC -pie" AR=aarch64-linux-gnu-ar CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ RANLIB=aarch64-linux-gnu-ranlib cmake -DCMAKE_VISIBILITY_INLINES_HIDDEN=OFF -DCMAKE_CXX_VISIBILITY_PRESET=default -DFMT_TEST=OFF ../../fmt/
	AR=aarch64-linux-gnu-ar CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ RANLIB=aarch64-linux-gnu-ranlib $(MAKE)
depends/jsoncpp/lib/libjsoncpp.a:
	mkdir -p depends/jsoncpp&&cd depends/jsoncpp
	CXXFLAGS="-fPIC -pie" cmake -DJSONCPP_WITH_TESTS=OFF -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF -DBUILD_SHARED_LIBS=OFF -DBUILD_OBJECT_LIBS=OFF ../../jsoncpp
	$(MAKE)
depends/jsoncpp-aarch64/lib/libjsoncpp.a:
	mkdir -p depends/jsoncpp-aarch64&&cd depends/jsoncpp-aarch64
	CXXFLAGS="-fPIC -pie" AR=aarch64-linux-gnu-ar CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ RANLIB=aarch64-linux-gnu-ranlib cmake -DJSONCPP_WITH_TESTS=OFF -DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF -DBUILD_SHARED_LIBS=OFF -DBUILD_OBJECT_LIBS=OFF ../../jsoncpp
	AR=aarch64-linux-gnu-ar CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ RANLIB=aarch64-linux-gnu-ranlib $(MAKE)
depends/mongo-c-driver/src/libmongoc/libmongoc-static-1.0.a:
	mkdir -p depends/mongo-c-driver&&cd depends/mongo-c-driver
	CFLAGS="-fPIC -pie" cmake -DENABLE_ICU=OFF -DENABLE_SASL=OFF -DENABLE_STATIC=ON -DENABLE_TESTS=OFF -DENABLE_EXAMPLES=OFF -DENABLE_SRV=OFF ../../mongodb/mongo-c-driver
	$(MAKE)
depends/mongo-cxx-driver/src/mongocxx/libmongocxx-static.a: depends/mongo-c-driver/src/libmongoc/libmongoc-static-1.0.a
	mkdir -p depends/mongo-cxx-driver&&cd depends/mongo-cxx-driver
	CXXFLAGS="-fPIC -pie -I$(CURDIR)/depends/mongo-c-driver/src/libbson/src/bson -I$(CURDIR)/depends/mongo-c-driver/src/libmongoc/src/mongoc -I$(CURDIR)/mongodb/mongo-c-driver/src/libbson/src" cmake -DBUILD_SHARED_LIBS=OFF -DBSONCXX_POLY_USE_STD=ON -DCMAKE_CXX_STANDARD=17 -DENABLE_TESTS=OFF -Dlibbson-static-1.0_DIR=$(CURDIR)/depends/mongo-c-driver/src/libbson -Dlibmongoc-static-1.0_DIR=$(CURDIR)/depends/mongo-c-driver/src/libmongoc ../../mongodb/mongo-cxx-driver
	$(MAKE)
depends/mongo-c-driver-aarch64/src/libmongoc/libmongoc-static-1.0.a:
	mkdir -p depends/mongo-c-driver-aarch64&&cd depends/mongo-c-driver-aarch64
	# Below: ssl is off because I don't want to waste time on it, we are not
	#        going to connect to the DB with ssl, and actually it's able to
	#        be compiled (static one) even when you enabled ssl, but shared
	#        one would fail, so that you will have to double run the make.
	CFLAGS="-fPIC -pie" AR=aarch64-linux-gnu-ar CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ RANLIB=aarch64-linux-gnu-ranlib cmake -DENABLE_SSL=OFF -DENABLE_SASL=OFF -DENABLE_ICU=OFF -DENABLE_STATIC=ON -DENABLE_TESTS=OFF -DENABLE_EXAMPLES=OFF -DENABLE_SRV=OFF ../../mongodb/mongo-c-driver
	AR=aarch64-linux-gnu-ar CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ RANLIB=aarch64-linux-gnu-ranlib $(MAKE)
depends/mongo-cxx-driver-aarch64/src/mongocxx/libmongocxx-static.a: depends/mongo-c-driver-aarch64/src/libmongoc/libmongoc-static-1.0.a
	mkdir -p depends/mongo-cxx-driver-aarch64&&cd depends/mongo-cxx-driver-aarch64
	AR=aarch64-linux-gnu-ar CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ RANLIB=aarch64-linux-gnu-ranlib CXXFLAGS="-fPIC -pie -I$(CURDIR)/depends/mongo-c-driver-aarch64/src/libbson/src/bson -I$(CURDIR)/depends/mongo-c-driver-aarch64/src/libmongoc/src/mongoc -I$(CURDIR)/mongodb/mongo-c-driver/src/libbson/src" cmake -DBUILD_SHARED_LIBS=OFF -DCMAKE_CXX_STANDARD=17 -DBSONCXX_POLY_USE_STD=ON -DENABLE_TESTS=OFF -Dlibbson-static-1.0_DIR=$(CURDIR)/depends/mongo-c-driver-aarch64/src/libbson -Dlibmongoc-static-1.0_DIR=$(CURDIR)/depends/mongo-c-driver-aarch64/src/libmongoc ../../mongodb/mongo-cxx-driver
	AR=aarch64-linux-gnu-ar CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ RANLIB=aarch64-linux-gnu-ranlib $(MAKE)
pv4: *.cpp *.h depends/libfmt/libfmt.a depends/jsoncpp/lib/libjsoncpp.a depends/mongo-cxx-driver/src/mongocxx/libmongocxx-static.a depends/mongo-c-driver/src/libmongoc/libmongoc-static-1.0.a
	g++ --std=c++20 main.cpp modules.cpp \
		utils.cpp action.cpp \
		-Wl,--whole-archive \
		depends/libfmt/libfmt.a depends/jsoncpp/lib/libjsoncpp.a \
		depends/mongo-cxx-driver/src/mongocxx/libmongocxx-static.a \
		depends/mongo-cxx-driver/src/bsoncxx/libbsoncxx-static.a \
		-Wl,--no-whole-archive \
		depends/mongo-c-driver/src/libmongoc/libmongoc-static-1.0.a \
		depends/mongo-c-driver/src/libbson/libbson-static-1.0.a \
		-Imongodb/mongo-cxx-driver/src/ -Idepends/mongo-cxx-driver/src/ \
		-Ijsoncpp/include -Ifmt/include -Ispdlog/include \
		-DSPDLOG_FMT_EXTERNAL -DSPDLOG_NO_THREAD_ID \
		-DSPDLOG_FUNCTION=__PRETTY_FUNCTION__ -rdynamic \
		-lssl -lcrypto -lzstd -lresolv -lz -o pv4
pv4-aarch64: *.cpp *.h depends/libfmt-aarch64/libfmt.a depends/jsoncpp-aarch64/lib/libjsoncpp.a depends/mongo-cxx-driver-aarch64/src/mongocxx/libmongocxx-static.a depends/mongo-c-driver-aarch64/src/libmongoc/libmongoc-static-1.0.a
	aarch64-linux-gnu-g++ -O9 --std=c++20 -DSPDLOG_FMT_EXTERNAL \
		-DSPDLOG_NO_THREAD_ID -DSPDLOG_FUNCTION=__PRETTY_FUNCTION__ \
		-rdynamic \
		main.cpp modules.cpp \
		utils.cpp action.cpp \
		-Wl,--whole-archive \
		depends/libfmt-aarch64/libfmt.a \
		depends/jsoncpp-aarch64/lib/libjsoncpp.a \
		depends/mongo-cxx-driver-aarch64/src/mongocxx/libmongocxx-static.a \
		depends/mongo-cxx-driver-aarch64/src/bsoncxx/libbsoncxx-static.a \
		-Wl,--no-whole-archive \
		depends/mongo-c-driver-aarch64/src/libmongoc/libmongoc-static-1.0.a \
		depends/mongo-c-driver-aarch64/src/libbson/libbson-static-1.0.a \
		-Imongodb/mongo-cxx-driver/src/ -Idepends/mongo-cxx-driver-aarch64/src/ \
		-Ijsoncpp/include -Ifmt/include -Ispdlog/include \
		-lssl -lcrypto -lzstd -lresolv -lz -o pv4-aarch64
