#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include "netapioverlay.h"
#include "posix_include.h"

static netapi::NetAPI* g_na = nullptr;

static netapi::DataSourceSingle* g_ds = nullptr;
static netapi::NetAPIOverlay* g_nao = nullptr;

extern "C" void CreateNetAPIOverlay(const uint8_t* data, const size_t size) {
    g_ds = new netapi::DataSourceSingle(data, size);
    g_nao = new netapi::NetAPIOverlay(*g_ds);
}

extern "C" void DestroyNetAPIOverlay(void) {
    delete g_nao;
    g_nao = nullptr;

    delete g_ds;
    g_ds = nullptr;
}

static netapi::NetAPI* getInstance(void) {
    if ( g_nao == nullptr ) {
        if ( g_na == nullptr ) {
            g_na = new netapi::NetAPI();
        }
        //printf("Warning: NetAPIOverlay object not instantiated\n");
        return g_na;
    }
    return g_nao;
}

#include "netapi_lib_impl.cpp"
