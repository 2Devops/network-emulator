#include <stddef.h>
#include <stdint.h>

#include "netapioverlay.h"

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    using namespace netapi;

    DataSourceSingle ds(data, size);
    NetAPIOverlay nao(ds);

    return 0;
}
