#all: netapi.o netapioverlay.o datasource.o netapi_lib.o
CC=clang
CXX=clang++
#CXXFLAGS=-Wall -Wextra -g -fsanitize=address -fsanitize-coverage=trace-pc-guard
#CXXFLAGS=-Wall -Wextra -g -O3 -fsanitize-coverage=trace-pc-guard,trace-cmp
CXXFLAGS=-Wall -Wextra -g -O3
all: libnetapi.so

netapi_impl.cpp netapi_method_decl.h netapioverlay_method_decl.h netapi_lib_impl.cpp netapi_ds_ids.h: gennetapi.py
	python gennetapi.py

netapi.o : netapi.cpp posix_include.h netapi_impl.cpp netapi_method_decl.h netapioverlay_method_decl.h netapi_lib_impl.cpp
	$(CXX) $(CXXFLAGS) -c -g -fPIC -Wall -std=c++14 netapi.cpp -o netapi.o

netapioverlay.o : netapioverlay.cpp posix_include.h netapi_impl.cpp netapi_method_decl.h netapioverlay_method_decl.h netapi_lib_impl.cpp netapi_ds_ids.h descriptorstate.h
	$(CXX) $(CXXFLAGS) -c -g -fPIC -Wall -std=c++14 netapioverlay.cpp -o netapioverlay.o

flagtester.o : flagtester.cpp flagtester.h
	$(CXX) $(CXXFLAGS) -c -g -fPIC -Wall -std=c++14 flagtester.cpp -o flagtester.o

artificialfailure.o : artificialfailure.cpp artificialfailure.h flagtester.h datasource.h failstate.h
	$(CXX) $(CXXFLAGS) -c -g -fPIC -Wall -std=c++14 artificialfailure.cpp -o artificialfailure.o

descriptorstate.o : descriptorstate.cpp descriptorstate.h netapi.h constants.h
	$(CXX) $(CXXFLAGS) -c -g -fPIC -Wall -std=c++14 descriptorstate.cpp -o descriptorstate.o

peer.o : peer.cpp posix_include.h netapi_impl.cpp netapi_method_decl.h netapioverlay_method_decl.h netapi_lib_impl.cpp
	$(CXX) $(CXXFLAGS) -c -g -fPIC -Wall -std=c++14 peer.cpp -o peer.o

datasource.o : datasource.cpp posix_include.h netapi_impl.cpp netapi_method_decl.h netapioverlay_method_decl.h netapi_lib_impl.cpp
	$(CXX) $(CXXFLAGS) -c -g -fPIC -Wall -std=c++14 datasource.cpp -o datasource.o

netapi_lib.o : netapi_lib.cpp posix_include.h netapi_impl.cpp netapi_method_decl.h netapioverlay_method_decl.h netapi_lib_impl.cpp
	$(CXX) $(CXXFLAGS) -c -g -fPIC -Wall -std=c++14 netapi_lib.cpp -o netapi_lib.o

libnetapi.so : netapi.o netapioverlay.o artificialfailure.o descriptorstate.o flagtester.o peer.o datasource.o netapi_lib.o
	$(CXX) $(CXXFLAGS) -shared -fPIC netapi.o netapioverlay.o descriptorstate.o peer.o datasource.o netapi_lib.o -o libnetapi.so -ldl

test: test.cpp
	$(CXX) $(CXXFLAGS) -g -std=c++11 -I beast-boost-1.67.0/include -I newboost/boost_1_67_0 test.cpp -o test -ldl newboost/boost_1_67_0/stage/lib/libboost_system.a -lpthread

clean:
	rm -rf netapi.o netapioverlay.o artificialfailure.o descriptorstate.o peer.o datasource.o netapi_lib.o libnetapi.so netapi_impl.cpp netapi_method_decl.h netapioverlay_method_decl.h netapi_lib_impl.cpp
	rm -rf test
