all : fuzzer-netapioverlay fuzzer-queue

fuzzer-netapioverlay : fuzzer-netapioverlay.cpp
	$(CXX) -I .. -D_GLIBCXX_DEBUG -fno-common -fsanitize=address -fsanitize=undefined -fsanitize-coverage=trace-pc-guard,trace-cmp -g -O3 fuzzer-netapioverlay.cpp ../datasource.cpp ../netapioverlay.cpp ../peer.cpp ../descriptorstate.cpp ../netapi.cpp $(LIBFUZZER_A_PATH) -o fuzzer-netapioverlay

fuzzer-queue : fuzzer-queue.cpp
	$(CXX) -I .. -D_GLIBCXX_DEBUG -fno-common -fsanitize=address -fsanitize=undefined -fsanitize-coverage=trace-pc-guard,trace-cmp -g -O3 fuzzer-queue.cpp ../datasource.cpp ../netapioverlay.cpp ../peer.cpp ../descriptorstate.cpp ../netapi.cpp $(LIBFUZZER_A_PATH) -o fuzzer-queue

clean:
	rm -rf fuzzer-netapioverlay fuzzer-queue
