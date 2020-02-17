#include "socket.h"
#include <unistd.h>
#include <errno.h>
#include <string.h>

using namespace netapi::test;

int main(void)
{
    auto server = new ConnectionThread();
    bool stop = false;
    server->Start([stop](Connection* connPtr) {
            connPtr->GetSocketRef().Create();
            connPtr->GetSockaddrInRef().Set(htons(9999));
            connPtr->Bind(true);
            connPtr->Listen(true);
            connPtr->Accept(true);
            connPtr->Shutdown(SHUT_WR, true);
            const unsigned char toSend[1] = {};
            printf("Calling send() on write-disabled socket returns: %ld\n", connPtr->Send(toSend, sizeof(toSend), MSG_NOSIGNAL, false));
            printf("errno is %d ('%s')\n", errno, strerror(errno));
            while ( stop ) { sleep(1); }
            });
    sleep(2);
    auto client = new ConnectionThread();
    client->Start([stop](Connection* connPtr) {
        connPtr->GetSocketRef().Create();
        connPtr->GetSockaddrInRef().Set(htons(9999), inet_addr("127.0.0.1"));
        connPtr->Connect();
            while ( stop ) { sleep(1); }
        });
    sleep(10);

    stop = true;
    delete server;
    delete client;
    return 0;
}
