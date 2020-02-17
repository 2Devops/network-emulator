#include "socket.h"
#include <unistd.h>

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
    sleep(2);

    stop = true;
    delete server;
    delete client;
    return 0;
}
