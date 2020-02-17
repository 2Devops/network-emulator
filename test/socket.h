#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstdint>
#include <exception>
#include <thread>
#include <functional>

namespace netapi {
namespace test {

class Exception : public std::exception {
    public:
        Exception() : std::exception() { }
};

class Socket {
    private:
        int sockfd = -1;
        bool set = false;
    public:
        Socket(void) { }
        void Set(const int _sockfd) {
            sockfd = _sockfd;
            set = true;
        }
        int Create(const int domain = AF_INET, const int type = SOCK_STREAM, const int protocol = 0) {
            sockfd = socket(domain, type, protocol);
            set = true;
            return sockfd;
        }

        int Get(void) const {
            if ( set == false ) {
                throw Exception();
            }
            return sockfd;
        }
};

class SockaddrIn {
    private:
        struct sockaddr_in sa_in = {};
        bool set = false;
    public:
        SockaddrIn(void) { }
        void Set(const unsigned short port, const unsigned long s_addr = INADDR_ANY, const short sin_family = AF_INET) {
            sa_in.sin_family = sin_family;
            sa_in.sin_addr.s_addr = s_addr;
            sa_in.sin_port = port;
            set = true;
        }
        struct sockaddr_in* GetPtr(void) {
            if ( set == false ) {
                throw Exception();
            }
            return &sa_in;
        }

        size_t Size(void) const {
            return sizeof(sa_in);
        }
};

class Connection {
    private:
        Socket socket;
        Socket connectedSocket;
        SockaddrIn sockaddrIn;
        bool bound = false;
        bool listening = false;
        bool connected = false;
        std::function<void(void)> onConnect;
    public:
        Connection(void) { }
        Socket& GetSocketRef(void) {
            return socket;
        }

        SockaddrIn& GetSockaddrInRef(void) {
            return sockaddrIn;
        }

        int Bind(const bool doThrow = false) {
            const int ret = bind(socket.Get(), (const struct sockaddr *)sockaddrIn.GetPtr(), sockaddrIn.Size());
            if ( ret == 0 ) {
                bound = true;
            } else if ( doThrow == true ) {
                throw Exception();
            }
            return ret;
        }

        int Listen(const bool doThrow = false, const int backlog = 3) {
            const int ret = listen(socket.Get(), backlog);
            if ( ret == 0 ) {
                listening = true;
            } else if ( doThrow == true ) {
                throw Exception();
            }
            return ret;
        }

        int Connect(const bool doThrow = false) {
            const int ret = connect(socket.Get(), (const struct sockaddr *)sockaddrIn.GetPtr(), sockaddrIn.Size());
            if ( ret == 0 ) {
                connected = true;
            } else if ( doThrow == true ) {
                throw Exception();
            }
            printf("Connected\n");
            return ret;
        }

        int Accept(const bool doThrow = false) {
            socklen_t addrlen = sockaddrIn.Size();
            const int ret = accept(socket.Get(), (struct sockaddr *)sockaddrIn.GetPtr(), &addrlen);
            if ( ret >= 1 ) {
                connected = true;
                connectedSocket.Set(ret);
            } else if ( doThrow == true ) {
                throw Exception();
            }
            printf("Accepted\n");
            return ret;
        }

        ssize_t Send(const void* buf, const size_t len, const int flags = 0, const bool doThrow = false) {
            const ssize_t ret = send(connectedSocket.Get(), buf, len, flags);
            if ( ret == -1 && doThrow == true ) {
                throw Exception();
            }
            return ret;
        }

        ssize_t Recv(void* buf, const size_t len, const int flags = 0, const bool doThrow = false) {
            const ssize_t ret = recv(connectedSocket.Get(), buf, len, flags);
            if ( ret == -1 && doThrow == true ) {
                throw Exception();
            }
            return ret;
        }

        int Shutdown(const int how, const bool doThrow = false) {
            const int ret = shutdown(connectedSocket.Get(), how);
            if ( ret == -1 && doThrow == true ) {
                throw Exception();
            }
            return ret;
        }

        void SetConnectCB(std::function<void(void)> callback) {
            onConnect = callback;
        }
};

class ConnectionThread {
    private:
        Connection connection;
        std::thread the_thread;
        bool stop_thread = false;
    public:
        ConnectionThread() :
            the_thread()
        {}

        ~ConnectionThread() {
            stop_thread = true;
            the_thread.join();
        }

        void Start(std::function<void(Connection* connPtr)> threadBody) {
            the_thread = std::thread(std::bind(threadBody, &connection));
        }

        Connection& GetConnectionRef(void) {
            return connection;
        }
};

} /* namespace test */
} /* namespace netapi */
