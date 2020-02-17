#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

typedef void (*CreateNetAPIOverlay_type)(const uint8_t*, const size_t);
typedef void (*DestroyNetAPIOverlay_type)(void);

CreateNetAPIOverlay_type CreateNetAPIOverlay = nullptr;
DestroyNetAPIOverlay_type DestroyNetAPIOverlay = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    CreateNetAPIOverlay = (CreateNetAPIOverlay_type)dlsym(RTLD_NEXT, "CreateNetAPIOverlay");
    DestroyNetAPIOverlay = (DestroyNetAPIOverlay_type)dlsym(RTLD_NEXT, "DestroyNetAPIOverlay");
    if ( CreateNetAPIOverlay == nullptr || DestroyNetAPIOverlay == nullptr ) {
        abort();
    }

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    CreateNetAPIOverlay(data, size);
    DestroyNetAPIOverlay();
    return 0;
}
