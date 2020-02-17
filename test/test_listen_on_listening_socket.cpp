#include "socket.h"
#include <unistd.h>

using namespace netapi::test;

int main(void)
{
    auto server = new ConnectionThread();
    bool stop = false;
    server->Start([stop](Connection* connPtr) mutable {
            connPtr->GetSocketRef().Create();
            connPtr->GetSockaddrInRef().Set(htons(9999));
            connPtr->Bind(true);
            connPtr->Listen(true);
            printf("Calling listen on a listening socket returns: %d\n", connPtr->Listen());
            while ( stop ) { sleep(1); }
            });

    sleep(2);
    stop = true;
    delete server;
    return 0;
}
