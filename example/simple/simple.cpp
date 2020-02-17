#include <string>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(void)
{
    uint8_t data[10240] = {0};
    {
        typedef void (*CreateNetAPIOverlay_type)(const uint8_t*, const size_t);
        CreateNetAPIOverlay_type CreateNetAPIOverlay = (CreateNetAPIOverlay_type)dlsym(RTLD_NEXT, "CreateNetAPIOverlay");
        CreateNetAPIOverlay(data, 10240);
    }

    {
        int sockfd;
        struct sockaddr_in serv_addr;

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if ( sockfd == -1 ) {
            printf("%s: could not create socket. errno: %d\n", __FUNCTION__, errno);
            exit(1);
        }

        memset(&serv_addr, '0', sizeof(serv_addr));
        if ( inet_aton("0.0.0.0", &serv_addr.sin_addr) == 0 ) {
            printf("%s: could not perform inet_aton. errno: %d\n", __FUNCTION__, errno);
            exit(1);
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(800);

        if ( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0 ) {
            printf("%s: could not connect. errno: %d\n", __FUNCTION__, errno);
            exit(1);
        }

        const std::string message("The message");
        if ( send(sockfd, message.c_str(), message.size() , 0) < 0 ) {
            printf("%s: could not send. errno: %d\n", __FUNCTION__, errno);
        }

        unsigned char recvbuffer[32];
        if ( recv(sockfd, recvbuffer, 32 , 0) == -1 ) {
            printf("%s: could not recv. errno: %d\n", __FUNCTION__, errno);
        }
    }

    {
        typedef void (*DestroyNetAPIOverlay_type)(void);
        DestroyNetAPIOverlay_type DestroyNetAPIOverlay = (DestroyNetAPIOverlay_type)dlsym(RTLD_NEXT, "DestroyNetAPIOverlay");
        DestroyNetAPIOverlay();
    }
    
    return 0;
}

