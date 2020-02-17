This is an emulator of the POSIX network API, designed for use with fuzzers via ```LD_PRELOAD```.

Fuzzers are often incomptatible with applications which perform network IO. Some libraries conveniently support buffer-based IO, used for example by [this OpenSSL fuzzer](https://github.com/openssl/openssl/blob/86cde3187d9acf6f331daff79ff2de87e86c6dc7/fuzz/server.c#L610).

But fuzzers rarely explore the full state space of the IO functions that are called by an application. Network functions like ```recv``` can return all kinds of errors at any moment, and can send or receive 1..N bytes for any N bytes requested. Such unusual (but legal) responses from the network API can activate code paths that have never been tested before and discover bugs previously overlooked.

I wrote this in mid 2018 and I haven't touched (or used) it since. It is unfinished and it needs more cowbell. I'm releasing it by popular request, and I currently cannot provide support, but I will accept PRs.
