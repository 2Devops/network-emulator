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

    SocketState socketState(100, AF_INET, SOCK_STREAM, 0);
    auto incomingQueue = socketState.GetQueue(SocketState::QUEUE_INCOMING);
    const auto enqueueData = ds.GetDataVec(0, 4096);
    incomingQueue.Enqueue(enqueueData);
    size_t i = 0;
    while ( incomingQueue.Size() ) {
        const auto amountToConsume = ds.GetInt(0, 0, incomingQueue.Size());
        const bool doAdvance = ds.GetInt(0, 0, 1) ? true : false;
        incomingQueue.Consume(amountToConsume, doAdvance);
        i++;
        if ( i == 3 ) {
            break;
        }
    }
    return 0;
}
