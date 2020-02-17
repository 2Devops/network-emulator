#include <cstring>
#include <cstdarg>
#include <dlfcn.h>
#include <errno.h>
#include <stdexcept>
#include <climits>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <bitset>
#include <netinet/in.h>
#include "netapioverlay.h"
#include "descriptorstate.h"
#include "netapi_ds_ids.h"
#include "flagtester.h"

namespace netapi {

/* class NetAPIOverlay */

NetAPIOverlay::NetAPIOverlay(DataSource& dataSource, size_t _maxDescriptors, int _failProbability)
    : ds(dataSource), maxDescriptors(_maxDescriptors), curSockFd(0x70000000) {

    if ( _failProbability < 0 ) {
        throw std::runtime_error("Negative fail probability");
    }

    failState.failProbability = _failProbability;
    failState.haveFailed = false;
    failState.failUnfailable = false;

    if ( curSockFd < 0 ) {
        throw std::runtime_error("Invalid curSockFd");
    }

    if ( maxDescriptors > (size_t)(0x7FFFFFFF - curSockFd) ) {
        throw std::runtime_error("maxDescriptors too high");
    }
}

NetAPIOverlay::~NetAPIOverlay(void) {
    for ( const auto& kv : descriptorStates ) {
        delete kv.second;
    }
    descriptorStates.clear();
}

/* Returns true if queue contains data after this call, false otherwise */
/* If called with len = 0, it only reports whether queue contains data or not */
bool NetAPIOverlay::enqueueDynamically(SocketState* socketState, const datasource_id peek_dsid, const datasource_id recv_dsid, const size_t len) {
    auto incomingQueue = socketState->GetQueue(SocketState::QUEUE_INCOMING);
    const bool haveQueueData = incomingQueue.Available();
    if ( len == 0 ) {
        return haveQueueData;
    }

    if ( haveQueueData == false ) {
        const bool doEnqueue = ds.GetInt(peek_dsid, 0, 1) ? true : false;
        if ( doEnqueue == true ) {
            const auto enqueueData = ds.GetDataVec(recv_dsid, len);
            incomingQueue.Enqueue(enqueueData);
            return true;
        }
    } else {
        return true;
    }

    return false;
}

bool NetAPIOverlay::haveSocketDataOrEnqueue(SocketState* socketState, const datasource_id numbytes_dsid, const datasource_id peek_dsid, const datasource_id recv_dsid, const size_t len) {

    /* Check if the queue has data without mutating it */
    if ( enqueueDynamically(socketState, 0, 0, 0) == true ) {
        return true;
    }

    const auto enqueueNumBytes = ds.GetInt(numbytes_dsid, 0, len);
    return enqueueDynamically(socketState, peek_dsid, recv_dsid, enqueueNumBytes);
}

int NetAPIOverlay::getNewFd(void) {
    if ( curSockFd >= (int)(0x70000000 + maxDescriptors) ) {
        throw std::runtime_error("Tried creating too many sockets");
    }

    return curSockFd++;
}

bool NetAPIOverlay::isOverlayDescriptor(const int fd) const {
    return fd >= (0x70000000) ? true : false;
}

bool NetAPIOverlay::haveDescriptor(const int fd) const {
    return descriptorStates.count(fd) != 0;
}

DescriptorState* NetAPIOverlay::getDescriptorState(const int fd) const {
    if ( haveDescriptor(fd) == false ) {
        throw std::runtime_error("fd not found");
    }

    DescriptorState* ret = descriptorStates.at(fd);
    if ( ret->IsDescriptorType(DescriptorState::DESC_TYPE_LINK) == true ) {
        ret = dynamic_cast<DescriptorLink*>(ret)->ResolveLink();
    }

    return ret;
}

bool NetAPIOverlay::isEpoll(const int fd) const {
    return getDescriptorState(fd)->IsDescriptorType(DescriptorState::DESC_TYPE_EPOLL);
}

bool NetAPIOverlay::isSocket(const int fd) const {
    return getDescriptorState(fd)->IsDescriptorType(DescriptorState::DESC_TYPE_SOCKET);
}

bool NetAPIOverlay::haveSocket(const int fd) const {
    if ( haveDescriptor(fd) == false ) {
        return false;
    }
    return isSocket(fd);
}

bool NetAPIOverlay::haveEpoll(const int fd) const {
    if ( haveDescriptor(fd) == false ) {
        return false;
    }
    return isEpoll(fd);
}

SocketState* NetAPIOverlay::getSocketState(const int fd) const {
    if ( isSocket(fd) == false ) {
        throw std::runtime_error("found descriptor is not a socket as expected");
    }

    return dynamic_cast<SocketState*>(getDescriptorState(fd));
}

EpollState* NetAPIOverlay::getEpollState(const int fd) const {
    if ( isEpoll(fd) == false ) {
        throw std::runtime_error("found descriptor is not an epoll descriptor as expected");
    }

    return dynamic_cast<EpollState*>(getDescriptorState(fd));
}

void NetAPIOverlay::addDescriptorState(DescriptorState* descriptorState) {
    if ( descriptorStates.count(descriptorState->GetFd()) != 0 ) {
        throw std::runtime_error("fd already in descriptorStates");
    }

    descriptorStates[descriptorState->GetFd()] = descriptorState;
}

void NetAPIOverlay::unimplemented(const std::string methodName) const {
    throw std::runtime_error("NetAPIOverlay method '" + methodName + "' not implemented");
}

void NetAPIOverlay::cb(const std::string methodName) const {
    if ( functionCallback != nullptr ) {
        functionCallback(methodName);
    }
    //printf("In %s\n", methodName.c_str());
}

void NetAPIOverlay::cb_delegate(const std::string methodName) const {
    //printf("Delegating %s\n", methodName.c_str());
}

void NetAPIOverlay::callMemoryCallback(const void* data, const size_t size, const int fd, const bool uninitialized, const int fd2) const {
    if ( memoryCallback != nullptr ) {
        bool overlay = true;

        if ( isOverlayDescriptor(fd) == false ) {
            overlay = false;
        } else if ( fd2 != -1 ) {
            if ( isOverlayDescriptor(fd2) == false ) {
                overlay = false;
            }
        }

        /* 'overlay' is now true if all (fd, and fd2 if not -1) are overlay descriptors */

        memoryCallback((const uint8_t*)data, size, overlay, uninitialized);
    }
}

void NetAPIOverlay::callMemoryCallbackMsghdr(const struct msghdr* msg, const int fd, const bool uninitialized) const {
    (void)fd; /* TODO remove if not needed */
    if ( memoryCallback != nullptr ) {
        callMemoryCallback(msg, sizeof(struct msghdr), uninitialized);

        /* spec:
         * The msg_name field points to a caller-allocated buffer that is used to return the source address if the socket is unconnected.
         * The caller should set msg_namelen to the size of this buffer before this call;  upon return from a successful call,
         * msg_namelen will contain the length of the returned address.  If the application does not need to know the source address,
         * msg_name can be specified as NULL.
         */
        if ( msg->msg_name != nullptr ) {
            callMemoryCallback(msg->msg_name, msg->msg_namelen, uninitialized);
        }

        /* spec:
         * The field msg_control, which has length msg_controllen, points to a buffer for other protocol control-related messages
         * or miscellaneous ancillary data.  When recvmsg() is called, msg_controllen should contain the length of the available buffer
         * in msg_control; upon return from a successful call it will contain the length of the control message sequence.
         */
        callMemoryCallback(msg->msg_control, msg->msg_controllen, uninitialized);

        for (size_t i = 0; i < msg->msg_iovlen; i++) {
            callMemoryCallback(msg->msg_iov + i, sizeof(*(msg->msg_iov)), uninitialized);
            if ( uninitialized == false ) {
                callMemoryCallback((msg->msg_iov + i)->iov_base, (msg->msg_iov + i)->iov_len, false);
            }
        }
    }
}

void NetAPIOverlay::callMemoryCallbackMMsghdr(const struct mmsghdr* msg, const int fd, const bool uninitialized) const {
    if ( memoryCallback != nullptr ) {
        callMemoryCallback(msg, sizeof(struct mmsghdr), uninitialized);
        callMemoryCallbackMsghdr(&(msg->msg_hdr), fd, uninitialized);
        /* TODO handle msg->msg_len */
    }
}

void NetAPIOverlay::callMemoryCallbackEpollEvent(const struct epoll_event* event, const int op, const int epfd, const bool uninitialized) const {
    (void)op; /* TODO remove if not needed */
    (void)epfd; /* TODO remove if not needed */
    if ( memoryCallback != nullptr ) {
        callMemoryCallback(event, sizeof(struct epoll_event), uninitialized);

        if ( uninitialized == false ) {
            /* process ptr, fd, u32, u64 members of event->data */
        }

    }
}

void NetAPIOverlay::callWarningCallback(const warning_t warning) const {
    if ( warningCallback != nullptr ) {
        printf("issue warning %u\n", warning);
        warningCallback(warning);
    }
}

void NetAPIOverlay::checkNullPointer(const void* p, const warning_t warning) const {
    if ( p == nullptr ) {
        callWarningCallback(warning);
    }
}

void NetAPIOverlay::SetRecvCallback(const recv_cb_t callback) {
    recvCallback = callback;
}

void NetAPIOverlay::SetFunctionCallback(const function_cb_t callback) {
    functionCallback = callback;
}

void NetAPIOverlay::SetMemoryCallback(const memory_cb_t callback) {
    memoryCallback = callback;
}

void NetAPIOverlay::SetWarningCallback(const warning_cb_t callback) {
    warningCallback = callback;
}

void NetAPIOverlay::SetContinueFailing(const bool _continueFailing) {
    failState.continueFailing = _continueFailing;
}

int NetAPIOverlay::socket(int domain, int type, int protocol) {
    cb(__FUNCTION__);

    bool doDelegate = false;
    /* Step 1. Input validation and scanning */
    {
        if ( domain != AF_INET ) {
            //throw std::runtime_error("socket: only AF_INET domains supported");
            doDelegate = true;
        }

        if ( type != SOCK_STREAM && type != SOCK_DGRAM ) {
            //throw std::runtime_error("socket: only SOCK_STREAM and SOCK_DGRAM types supported");
            doDelegate = true;
        }

        if ( type == SOCK_STREAM ) {
            if ( protocol == 0 || protocol == IPPROTO_TCP ) {
                /* Valid */
            } else {
                doDelegate = true;
            }
        } else if ( type == SOCK_DGRAM ) {
            if ( protocol == 0 || protocol == IPPROTO_UDP ) {
                /* Valid */
            } else {
                doDelegate = true;
            }
        }
    }

    doDelegate = false; /* XXX */
    /* Step 2. Delegation */
    /* (not applicable) */
    {
        if ( doDelegate == true ) {
            cb_delegate(__FUNCTION__);
            return NetAPI::socket(domain, type, protocol);
        }
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_SOCKET,
                NETAPI_DSID_FAIL_CHOICE_SOCKET,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        auto socketState = new SocketState(getNewFd(), domain, type, protocol);

        addDescriptorState(socketState);

        return socketState->GetFd();
    }
}

int NetAPIOverlay::connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        checkNullPointer(addr, WARNING_CONNECT_ADDR_NULLPTR);
        callMemoryCallback(addr, addrlen, sockfd);
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::connect(sockfd, addr, addrlen);
    }

    /* Step 3. Artificial failure */
    {
        /* Viable errno's:
         * ECONNREFUSED No-one listening on the remote address.
         * ENETUNREACH Network is unreachable.
         * ETIMEDOUT Timeout while attempting connection. [...]
         */
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_CONNECT,
                NETAPI_DSID_FAIL_CHOICE_CONNECT,
                {ECONNREFUSED, ENETUNREACH, ETIMEDOUT}
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        /* TODO
         * return 0 right here if socket is UDP.
         * Nothing at all happens in this case
         * (per tests/connect_on_udp_socket.c) */

        auto socketState = getSocketState(sockfd);

        if ( socketState->IsConnected() ) {
            callWarningCallback(WARNING_DOUBLE_CONNECT);
            /* spec: EISCONN The socket is already connected. */
            errno = EISCONN;
            return -1;
        }

        if ( socketState->IsListening() ) {
            /* connect()ing on a listening socket is not explicitly handled by the spec,
             * but tests/connect_on_listening_socket.c shows that error EISCONN is returned */
            errno = EISCONN;
            return -1;
        }

        socketState->SetConnected();
        socketState->SetPeerName(addr, addrlen);

        return 0;
    }
}

int NetAPIOverlay::bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        checkNullPointer(addr, WARNING_BIND_ADDR_NULLPTR);
        callMemoryCallback(addr, addrlen, sockfd);
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::bind(sockfd, addr, addrlen);
    }

    /* Step 3. Artificial failure */
    {
        /* Viable errno's:
         *
         * EADDRINUSE The given address is already in use.
         */
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_BIND,
                NETAPI_DSID_FAIL_CHOICE_BIND,
                {EADDRINUSE}
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        auto socketState = getSocketState(sockfd);

        if ( socketState->IsBound() ) {
            /* spec: EINVAL The socket is already bound to an address. */
            /* see also: tests/double_bind.c */
            errno = EINVAL;
            return -1;
        }

        socketState->SetBound();

        socketState->SetSocketName(addr, addrlen);
        return 0;
    }
}

int NetAPIOverlay::shutdown(int sockfd, int how) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    /* (none -- 'how' implicitly validation in step 4) */

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::shutdown(sockfd, how);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_SHUTDOWN,
                NETAPI_DSID_FAIL_CHOICE_SHUTDOWN,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        auto socketState = getSocketState(sockfd);

        switch ( how ) {
            case    SHUT_RD:
                socketState->DisableRead();
                break;
            case    SHUT_WR:
                socketState->DisableWrite();
                break;
            case    SHUT_RDWR:
                socketState->DisableRead();
                socketState->DisableWrite();
                break;
            default:
                /* spec: EINVAL An invalid value was specified in how */
                callWarningCallback(WARNING_SHUTDOWN_INVALID_HOW);
                errno = EINVAL;
                return -1;
        }
    }

    return 0;
}

int NetAPIOverlay::listen(int sockfd, int backlog) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        if ( backlog < 0 ) {
            callWarningCallback(WARNING_LISTEN_BACKLOG_INVALID);
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::listen(sockfd, backlog);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_LISTEN,
                NETAPI_DSID_FAIL_CHOICE_LISTEN,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        auto socketState = getSocketState(sockfd);

        if ( socketState->IsListening() ) {
            /* TEST refer to test_listen_on_listening_socket.cpp */
            callWarningCallback(WARNING_DOUBLE_LISTEN);
            return 0;
        }

        if ( socketState->IsBound() == false ) {
            callWarningCallback(WARNING_LISTEN_UNBOUND);
            socketState->SetBound();
            /* https://stackoverflow.com/questions/741061/listen-without-calling-bind
             * TL;DR listening on unbound socket is OK, but OS fills in its struct sockaddr,
             * can be retrieved with getsockname */
            /* TODO socketState->SetSocketName() */
            abort();
        }

        if ( socketState->IsConnected() ) {
            callWarningCallback(WARNING_LISTEN_CONNECTED);
            /* TEST Refer to test_listen_on_connected_socket.cpp */
            return 0;
        }

        socketState->SetListening();

        return 0;
    }
}

/* Handles both accept and accept4 */
int NetAPIOverlay::accept_work(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags, const bool is_accept4, ArtificialFailure& artificialFailure) {
    /* Step 1. Input validation and scanning */
    {
        /* No null pointer checks -- addr, addrlen being NULL is allowed */

        if ( addrlen != nullptr ) {
            callMemoryCallback(addrlen, sizeof(socklen_t), sockfd, true); /* points to potentially uninitialized memory */
            callMemoryCallback(addr, *addrlen, sockfd, true); /* points to potentially uninitialized memory */
        }

        if ( addr == nullptr && addrlen != nullptr ) {
            /* spec: When addr is NULL, nothing is filled in; in this case, addrlen is not used, and should also be NULL. */
            if ( is_accept4 == false ) {
                callWarningCallback(WARNING_ACCEPT_ADDRLEN_NOT_NULL);
            } else {
                callWarningCallback(WARNING_ACCEPT4_ADDRLEN_NOT_NULL);
            }
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        if ( is_accept4 == false ) {
            cb_delegate("accept");
            return NetAPI::accept(sockfd, addr, addrlen);
        } else {
            cb_delegate("accept4");
            return NetAPI::accept4(sockfd, addr, addrlen, flags);
        }
    }

    /* Step 3. Artificial failure */
    {
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        auto socketState = getSocketState(sockfd);

        /* Check for invalid flags */
        {
            /* Only accept4 has flags */
            if ( is_accept4 == true ) {
                const static FlagTester flagTester({SOCK_NONBLOCK, SOCK_CLOEXEC, SOCK_NONBLOCK | SOCK_CLOEXEC});
                if ( flagTester.IsValid(flags) == false ) {
                    callWarningCallback(WARNING_ACCEPT4_INV_FLAGS);
                    /* spec: EINVAL (accept4()) invalid value in flags. */
                    errno = EINVAL;
                    return -1;
                }
            }
        }

        switch ( flags ) {
            case    SOCK_NONBLOCK:
                socketState->SetNonBlocking();
                break;
            case    SOCK_CLOEXEC:
                socketState->SetCloseOnExec();
                break;
            case    (SOCK_NONBLOCK | SOCK_CLOEXEC):
                socketState->SetNonBlocking();
                socketState->SetCloseOnExec();
                break;
        }

        if ( socketState->GetType() != SOCK_STREAM ) {
            /* spec: EOPNOTSUPP The referenced socket is not of type SOCK_STREAM. */
            errno = EOPNOTSUPP;
            return -1;
        }

        if ( socketState->IsConnected() ) {
            /* Accept on an already connected socket.
             * TEST Refer to test_accept_on_accepted_socket.cpp
             * This is OK and will fill in the sockaddr struct with info about
             * the newly connected peer.
             * TODO
             */
            abort();
        }

        if ( socketState->IsListening() == false ) {
            /* spec: EINVAL Socket is not listening for connections, or addrlen is invalid (e.g., is negative). */
            /* note: addrlen is unsigned so it cannot be negative - Guido */
            if ( is_accept4 == false ) {
                callWarningCallback(WARNING_ACCEPT_NOT_LISTENING);
            } else {
                callWarningCallback(WARNING_ACCEPT4_NOT_LISTENING);
            }
            errno = EINVAL;
            return -1;
        }


        if ( addr != nullptr ) {
            /* TODO:
             * 1. Generate a sockaddr
             * 2. socketState->SetPeerName();
             * 3. store it in 'addr'/'addrlen': socketState->WritePeerName(addr, addrlen);
             */
        }

        /* TODO untested */
        auto newSocketState = new SocketState(
                getNewFd(),
                socketState->GetDomain(),
                socketState->GetType(),
                socketState->GetProtocol());

        addDescriptorState(newSocketState);

        newSocketState->SetConnected();

        return newSocketState->GetFd();
    }
}

int NetAPIOverlay::accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    cb(__FUNCTION__);

    /* Viable errno's:
     *
     * ECONNABORTED A connection has been aborted
     * EPROTO Protocol error
     * (Linux only) EPERM Firewall rules forbid connection
     *
     * (TODO)
     * In addition, network errors for the new socket and as defined for the protocol may be returned.
     * Various Linux kernels can return other errors such as ENOSR, ESOCKTNOSUPPORT, EPROTONOSUPPORT, ETIMEDOUT.
     * The value ERESTARTSYS may be seen during a trace.
     */
    ArtificialFailure artificialFailure(ds,
            failState,
            NETAPI_DSID_FAIL_ACCEPT,
            NETAPI_DSID_FAIL_CHOICE_ACCEPT,
            {ECONNABORTED, EPROTO, EPERM}
            );

    return accept_work(sockfd, addr, addrlen, 0, false, artificialFailure);
}

int NetAPIOverlay::accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    cb(__FUNCTION__);

    /* Viable errno's:
     *
     * ECONNABORTED A connection has been aborted
     * EPROTO Protocol error
     * (Linux only) EPERM Firewall rules forbid connection
     *
     * (TODO)
     * In addition, network errors for the new socket and as defined for the protocol may be returned.
     * Various Linux kernels can return other errors such as ENOSR, ESOCKTNOSUPPORT, EPROTONOSUPPORT, ETIMEDOUT.
     * The value ERESTARTSYS may be seen during a trace.
     */
    ArtificialFailure artificialFailure(ds,
            failState,
            NETAPI_DSID_FAIL_ACCEPT4,
            NETAPI_DSID_FAIL_CHOICE_ACCEPT4,
            {ECONNABORTED, EPROTO, EPERM}
            );

    return accept_work(sockfd, addr, addrlen, flags, true, artificialFailure);
}

int NetAPIOverlay::getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
    cb(__FUNCTION__);


    /* Step 1. Input validation and scanning */
    {
        if ( optval != nullptr ) {
            /* TODO WRITETEST optval, optlen might be allowed to point to invalid addresses depending on optname? */
            callMemoryCallback(optval, *optlen, sockfd, true); /* points to potentially uninitialized memory */
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::getsockopt(sockfd, level, optname, optval, optlen);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_GETSOCKOPT,
                NETAPI_DSID_FAIL_CHOICE_GETSOCKOPT,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

#if 0
   Socket options
       The socket options listed below can be set by using setsockopt(2) and read with getsockopt(2) with the socket level set to SOL_SOCKET for all sockets.  Unless otherwise noted, optval is a pointer to an int.

       SO_ACCEPTCONN
              Returns a value indicating whether or not this socket has been marked to accept connections with listen(2).  The value 0 indicates that this is not a listening socket, the value 1 indicates that this is a  lis‐
              tening socket.  This socket option is read-only.

       SO_BINDTODEVICE
              Bind  this  socket  to a particular device like “eth0”, as specified in the passed interface name.  If the name is an empty string or the option length is zero, the socket device binding is removed.  The passed
              option is a variable-length null-terminated interface name string with the maximum size of IFNAMSIZ.  If a socket is bound to an interface, only packets received from that particular interface are processed  by
              the socket.  Note that this works only for some socket types, particularly AF_INET sockets.  It is not supported for packet sockets (use normal bind(2) there).

              Before  Linux  3.8,  this  socket  option could be set, but could not retrieved with getsockopt(2).  Since Linux 3.8, it is readable.  The optlen argument should contain the buffer size available to receive the
              device name and is recommended to be IFNAMSZ bytes.  The real device name length is reported back in the optlen argument.

       SO_BROADCAST
              Set or get the broadcast flag.  When enabled, datagram sockets are allowed to send packets to a broadcast address.  This option has no effect on stream-oriented sockets.

       SO_BSDCOMPAT
              Enable BSD bug-to-bug compatibility.  This is used by the UDP protocol module in Linux 2.0 and 2.2.  If enabled, ICMP errors received for a UDP socket will not be passed to the user program.   In  later  kernel
              versions,  support  for  this option has been phased out: Linux 2.4 silently ignores it, and Linux 2.6 generates a kernel warning (printk()) if a program uses this option.  Linux 2.0 also enabled BSD bug-to-bug
              compatibility options (random header changing, skipping of the broadcast flag) for raw sockets with this option, but that was removed in Linux 2.2.

       SO_DEBUG
              Enable socket debugging.  Only allowed for processes with the CAP_NET_ADMIN capability or an effective user ID of 0.

       SO_DOMAIN (since Linux 2.6.32)
              Retrieves the socket domain as an integer, returning a value such as AF_INET6.  See socket(2) for details.  This socket option is read-only.

       SO_ERROR
              Get and clear the pending socket error.  This socket option is read-only.  Expects an integer.

       SO_DONTROUTE
              Don't send via a gateway, send only to directly connected hosts.  The same effect can be achieved by setting the MSG_DONTROUTE flag on a socket send(2) operation.  Expects an integer boolean flag.

       SO_KEEPALIVE
              Enable sending of keep-alive messages on connection-oriented sockets.  Expects an integer boolean flag.

       SO_LINGER
              Sets or gets the SO_LINGER option.  The argument is a linger structure.

                  struct linger {
                      int l_onoff;    /* linger active */
                      int l_linger;   /* how many seconds to linger for */
                  };

              When enabled, a close(2) or shutdown(2) will not return until all queued messages for the socket have been successfully sent or the linger timeout has been reached.  Otherwise, the call returns immediately  and
              the closing is done in the background.  When the socket is closed as part of exit(2), it always lingers in the background.

       SO_MARK (since Linux 2.6.25)
              Set  the  mark  for each packet sent through this socket (similar to the netfilter MARK target but socket-based).  Changing the mark can be used for mark-based routing without netfilter or for packet filtering.
              Setting this option requires the CAP_NET_ADMIN capability.

       SO_OOBINLINE
              If this option is enabled, out-of-band data is directly placed into the receive data stream.  Otherwise, out-of-band data is passed only when the MSG_OOB flag is set during receiving.

       SO_PASSCRED
              Enable or disable the receiving of the SCM_CREDENTIALS control message.  For more information see unix(7).

       SO_PEEK_OFF (since Linux 3.4)
              This option, which is currently supported only for unix(7) sockets, sets the value of the "peek offset" for the recv(2) system call when used with MSG_PEEK flag.

              When this option is set to a negative value (it is set to -1 for all new sockets), traditional behavior is provided: recv(2) with the MSG_PEEK flag will peek data from the front of the queue.

              When the option is set to a value greater than or equal to zero, then the next peek at data queued in the socket will occur at the byte offset specified by the option value.  At the same time, the "peek offset"
              will be incremented by the number of bytes that were peeked from the queue, so that a subsequent peek will return the next data in the queue.

              If  data  is removed from the front of the queue via a call to recv(2) (or similar) without the MSG_PEEK flag, the "peek offset" will be decreased by the number of bytes removed.  In other words, receiving data
              without the MSG_PEEK flag will cause the "peek offset" to be adjusted to maintain the correct relative position in the queued data, so that a subsequent  peek  will  retrieve  the  data  that  would  have  been
              retrieved had the data not been removed.

              For datagram sockets, if the "peek offset" points to the middle of a packet, the data returned will be marked with the MSG_TRUNC flag.

              The following example serves to illustrate the use of SO_PEEK_OFF.  Suppose a stream socket has the following queued input data:

                  aabbccddeeff

              The following sequence of recv(2) calls would have the effect noted in the comments:

                  int ov = 4;                  // Set peek offset to 4
                  setsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &ov, sizeof(ov));

                  recv(fd, buf, 2, MSG_PEEK);  // Peeks "cc"; offset set to 6
                  recv(fd, buf, 2, MSG_PEEK);  // Peeks "dd"; offset set to 8
                  recv(fd, buf, 2, 0);         // Reads "aa"; offset set to 6
                  recv(fd, buf, 2, MSG_PEEK);  // Peeks "ee"; offset set to 8

       SO_PEERCRED
              Return  the credentials of the foreign process connected to this socket.  This is possible only for connected AF_UNIX stream sockets and AF_UNIX stream and datagram socket pairs created using socketpair(2); see
              unix(7).  The returned credentials are those that were in effect at the time of the call to connect(2) or socketpair(2).  The argument is a ucred structure; define the _GNU_SOURCE feature test macro  to  obtain
              the definition of that structure from <sys/socket.h>.  This socket option is read-only.

       SO_PRIORITY
              Set  the  protocol-defined  priority  for  all  packets  to  be sent on this socket.  Linux uses this value to order the networking queues: packets with a higher priority may be processed first depending on the
              selected device queueing discipline.  Setting a priority outside the range 0 to 6 requires the CAP_NET_ADMIN capability.

       SO_PROTOCOL (since Linux 2.6.32)
              Retrieves the socket protocol as an integer, returning a value such as IPPROTO_SCTP.  See socket(2) for details.  This socket option is read-only.

       SO_RCVBUF
              Sets or gets the maximum socket receive buffer in bytes.  The kernel doubles this value (to allow space for bookkeeping overhead) when it is set using setsockopt(2), and this doubled value is returned  by  get‐
              sockopt(2).   The  default value is set by the /proc/sys/net/core/rmem_default file, and the maximum allowed value is set by the /proc/sys/net/core/rmem_max file.  The minimum (doubled) value for this option is
              256.

       SO_RCVBUFFORCE (since Linux 2.6.14)
              Using this socket option, a privileged (CAP_NET_ADMIN) process can perform the same task as SO_RCVBUF, but the rmem_max limit can be overridden.

       SO_RCVLOWAT and SO_SNDLOWAT
              Specify the minimum number of bytes in the buffer until the socket layer will pass the data to the protocol (SO_SNDLOWAT) or the user on receiving (SO_RCVLOWAT).  These two values are initialized to 1.  SO_SND‐
              LOWAT  is  not  changeable  on  Linux  (setsockopt(2)  fails  with  the  error ENOPROTOOPT).  SO_RCVLOWAT is changeable only since Linux 2.4.  The select(2) and poll(2) system calls currently do not respect the
              SO_RCVLOWAT setting on Linux, and mark a socket readable when even a single byte of data is available.  A subsequent read from the socket will block until SO_RCVLOWAT bytes are available.

       SO_RCVTIMEO and SO_SNDTIMEO
              Specify the receiving or sending timeouts until reporting an error.  The argument is a struct timeval.  If an input or output function blocks for this period of time, and data has been  sent  or  received,  the
              return  value  of  that  function  will  be the amount of data transferred; if no data has been transferred and the timeout has been reached, then -1 is returned with errno set to EAGAIN or EWOULDBLOCK, or EIN‐
              PROGRESS (for connect(2)) just as if the socket was specified to be nonblocking.  If the timeout is set to zero (the default), then the operation will never timeout.  Timeouts only have effect for system  calls
              that perform socket I/O (e.g., read(2), recvmsg(2), send(2), sendmsg(2)); timeouts have no effect for select(2), poll(2), epoll_wait(2), and so on.

       SO_REUSEADDR
              Indicates  that  the  rules  used in validating addresses supplied in a bind(2) call should allow reuse of local addresses.  For AF_INET sockets this means that a socket may bind, except when there is an active
              listening socket bound to the address.  When the listening socket is bound to INADDR_ANY with a specific port then it is not possible to bind to this port for any local address.  Argument is an integer  boolean
              flag.

       SO_REUSEPORT (since Linux 3.9)
              Permits  multiple AF_INET or AF_INET6 sockets to be bound to an identical socket address.  This option must be set on each socket (including the first socket) prior to calling bind(2) on the socket.  To prevent
              port hijacking, all of the processes binding to the same address must have the same effective UID.  This option can be employed with both TCP and UDP sockets.

              For TCP sockets, this option allows accept(2) load distribution in a multi-threaded server to be improved by using a distinct listener socket for each thread.  This provides improved load distribution  as  com‐
              pared to traditional techniques such using a single accept(2)ing thread that distributes connections, or having multiple threads that compete to accept(2) from the same socket.

              For  UDP sockets, the use of this option can provide better distribution of incoming datagrams to multiple processes (or threads) as compared to the traditional technique of having multiple processes compete to
              receive datagrams on the same socket.

       SO_RXQ_OVFL (since Linux 2.6.33)
              Indicates that an unsigned 32-bit value ancillary message (cmsg) should be attached to received skbs indicating the number of packets dropped by the socket between the last received  packet  and  this  received
              packet.

       SO_SNDBUF
              Sets  or gets the maximum socket send buffer in bytes.  The kernel doubles this value (to allow space for bookkeeping overhead) when it is set using setsockopt(2), and this doubled value is returned by getsock‐
              opt(2).  The default value is set by the /proc/sys/net/core/wmem_default file and the maximum allowed value is set by the /proc/sys/net/core/wmem_max file.  The minimum (doubled) value for this option is 2048.

       SO_SNDBUFFORCE (since Linux 2.6.14)
              Using this socket option, a privileged (CAP_NET_ADMIN) process can perform the same task as SO_SNDBUF, but the wmem_max limit can be overridden.

       SO_TIMESTAMP
              Enable or disable the receiving of the SO_TIMESTAMP control message.  The timestamp control message is sent with level SOL_SOCKET and the cmsg_data field is a struct timeval indicating the reception time of the
              last packet passed to the user in this call.  See cmsg(3) for details on control messages.

       SO_TYPE
              Gets the socket type as an integer (e.g., SOCK_STREAM).  This socket option is read-only.

       SO_BUSY_POLL (since Linux 3.11)
              Sets  the  approximate  time  in  microseconds  to  busy  poll  on  a  blocking  receive  when  there is no data.  Increasing this value requires CAP_NET_ADMIN.  The default for this option is controlled by the
              /proc/sys/net/core/busy_read file.

              The value in the /proc/sys/net/core/busy_poll file determines how long select(2) and poll(2) will busy poll when they operate on sockets with SO_BUSY_POLL set and no events to report are found.

              In both cases, busy polling will only be done when the socket last received data from a network device that supports this option.

              While busy polling may improve latency of some applications, care must be taken when using it since this will increase both CPU utilization and power usage.
#endif

    /* Step 4. State mutation, output generation */
    {
        if ( level != SOL_SOCKET ) {
            printf("Only SOL_SOCKET supported in getsockopt\n");
            abort();
        }

        switch ( optname ) {
            case SO_ERROR:
                /* TODO */
                return 0;
            case SO_REUSEADDR:
                /* TODO ? */
                return 0;
            default:
                /* Unsupported getsockopt optname */
                /* TODO */
                unimplemented(__FUNCTION__);
                return -1;
        }
    }
}

int NetAPIOverlay::setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        if ( optval != nullptr ) {
            /* TODO WRITETEST optval, optlen might be allowed to point to invalid addresses depending on optname? */
            callMemoryCallback(optval, optlen, sockfd);
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::setsockopt(sockfd, level, optname, optval, optlen);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_SETSOCKOPT,
                NETAPI_DSID_FAIL_CHOICE_SETSOCKOPT,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        /* TODO */
        return 0;

        unimplemented(__FUNCTION__);
        return -1;
    }
}

ssize_t NetAPIOverlay::send(int sockfd, const void *buf, size_t len, int flags) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        checkNullPointer(buf, WARNING_SEND_BUF_NULLPTR);
        callMemoryCallback(buf, len, sockfd);
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::send(sockfd, buf, len, flags);
    }

    /* Step 3. Artificial failure */
    {
        /* Viable errno's:
         *
         * ECONNRESET Connection reset by peer. */

        /* ENOBUFS The output queue for a network interface was full.  This generally indicates that the
         * interface has stopped sending, but may be caused by transient congestion.
         */

        /* spec: On success, these calls return the number of bytes sent.
         * On error, -1 is returned, and errno is set appropriately.
         */
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_SEND,
                NETAPI_DSID_FAIL_CHOICE_SEND,
                {ECONNRESET, ENOBUFS}
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        /* Check for invalid flags */
        {
            const static FlagTester flagTester({MSG_CONFIRM, MSG_DONTROUTE, MSG_DONTWAIT, MSG_EOR, MSG_MORE, MSG_NOSIGNAL, MSG_OOB});
            if ( flagTester.IsValid(flags) == false ) {
                callWarningCallback(WARNING_SEND_INV_FLAGS);
                /* TODO WRITETEST verify with a test that this is the errno for this situation */
                /* spec: EOPNOTSUPP Some bit in the flags argument is inappropriate for the socket type. */
                errno = EOPNOTSUPP;
                return -1;
            }
        }

        if ( haveSocket(sockfd) == false ) {
            /* spec: ENOTSOCK The file descriptor sockfd does not refer to a socket. */
            errno = ENOTSOCK;
            return -1;
        }

        const auto socketState = getSocketState(sockfd);

        if ( socketState->IsConnected() == false ) {
            /* spec: EDESTADDRREQ The socket is not connection-mode, and no peer address is set. */
            errno = EDESTADDRREQ;
            return -1;
        }

        if ( flags & MSG_CONFIRM ) {
            /* spec: Only valid on SOCK_DGRAM and SOCK_RAW sockets and currently implemented only for IPv4 and IPv6. */
            if ( socketState->GetType() != SOCK_DGRAM && socketState->GetType() != SOCK_RAW ) {
                callWarningCallback(WARNING_SEND_INV_MSG_CONFIRM);
                return -1;
            }
        }

        if ( flags & MSG_DONTROUTE ) {
            /* TODO */
            /* spec: This is defined only for protocol families that route; packet sockets don't. */
        }

        if ( socketState->IsNonBlocking() == false || flags & MSG_DONTWAIT ) {
            /* spec:
             * Enables nonblocking operation; if the operation would block, EAGAIN or EWOULDBLOCK is returned.
             * This provides similar behavior to setting the O_NONBLOCK flag (via the fcntl(2) F_SETFL operation),
             * but differs in that MSG_DONTWAIT is a per-call option, whereas O_NONBLOCK is a setting on the
             * open file description (see open(2)), which will affect all threads in the calling process and as well as
             * other processes that hold file descriptors referring to the same open file description.
             */
            /* TODO this needs to be handled in step 3 */
        }

        if ( flags & MSG_EOR ) {
            /* TODO */
            /* Terminates a record (when this notion is supported, as for sockets of type SOCK_SEQPACKET). */
        }

        if ( flags & MSG_MORE ) {
            /* Do nothing */

            /* spec:
             * The caller has more data to send. This flag is used with TCP sockets to obtain the same effect as the
             * TCP_CORK socket option (see tcp(7)), with the difference that this flag can be set on a per-call basis.
             *
             * Since Linux 2.6, this flag is also supported for UDP sockets, and informs the kernel to package all of
             * the data sent in calls with this flag set into a single datagram which is transmitted only when a call is
             * performed that does not specify this flag. (See also the UDP_CORK socket option described in udp(7).)
            */
        }

        if ( flags & MSG_NOSIGNAL ) {
            /* TODO */
            /* spec:
             * Don't generate a SIGPIPE signal if the peer on a stream-oriented socket has closed the connection.
             * The EPIPE error is still returned. This provides similar behavior to using sigaction(2) to ignore SIGPIPE,
             * but, whereas MSG_NOSIGNAL is a per-call feature, ignoring SIGPIPE sets a process attribute that affects
             * all threads in the process.
             */
        }

        if ( flags & MSG_OOB ) {
            /* TODO */
            /* spec:
             * Sends out-of-band data on sockets that support this notion (e.g., of type SOCK_STREAM); the underlying
             * protocol must also support out-of-band data.
             */
        }

        if ( socketState->IsWriteDisabled() ) {
            /* TEST Refer to test_send_on_write-disabled_socket.cpp */
            errno = EPIPE;
            return -1;
        }

        const auto numBytesSent = ds.GetInt(NETAPI_DSID_NUMBYTES_SEND, 0, len);

        return numBytesSent;
    }
}

ssize_t NetAPIOverlay::recv(int sockfd, void *buf, size_t len, int flags) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        checkNullPointer(buf, WARNING_RECV_BUF_NULLPTR);
        callMemoryCallback(buf, len, sockfd, true); /* points to potentially uninitialized memory */
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::recv(sockfd, buf, len, flags);
    }

    /* Step 3. Artificial failure */
    {
        if ( flags & MSG_DONTWAIT ) {
            /* spec on MSG_DONTWAIT:
             * Enables nonblocking operation; if the operation would block, the call fails with the error EAGAIN or EWOULDBLOCK. */
            ArtificialFailure artificialFailure(ds,
                    failState,
                    NETAPI_DSID_FAIL_RECV,
                    NETAPI_DSID_FAIL_CHOICE_RECV,
                    {EAGAIN, EWOULDBLOCK}
                    );
            if ( artificialFailure.GetFailure() == true ) {
                return -1;
            }
        } else {
            ArtificialFailure artificialFailure(ds,
                    failState,
                    NETAPI_DSID_FAIL_RECV,
                    NETAPI_DSID_FAIL_CHOICE_RECV,
                    {} /* no viable errno's */
                    );
            if ( artificialFailure.GetFailure() == true ) {
                return -1;
            }
        }

    }

    /* Step 4. State mutation, output generation */
    {
        /* Check for invalid flags */
        {
            const static FlagTester flagTester({MSG_DONTWAIT, MSG_ERRQUEUE, MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_WAITALL});
            if ( flagTester.IsValid(flags) == false ) {
                callWarningCallback(WARNING_RECV_INV_FLAGS);
                /* TODO WRITETEST verify with a test that this is the errno for this situation */
                /* spec: EINVAL Invalid argument passed. */
                errno = EINVAL;
                return -1;
            }
        }

        if ( haveSocket(sockfd) == false ) {
            /* spec: ENOTSOCK The file descriptor sockfd does not refer to a socket. */
            errno = ENOTSOCK;
            return -1;
        }

        const auto socketState = getSocketState(sockfd);
        auto incomingQueue = socketState->GetQueue(SocketState::QUEUE_INCOMING);

        if ( socketState->IsConnected() == false && socketState->IsConnectionOriented() == true ) {
            /* spec: EINVAL Invalid argument passed. */
            errno = EINVAL;
            return -1;
        }

        if ( socketState->IsReadDisabled() ) {
            /* TEST Refer to test_recv_on_write-disabled_socket.cpp.
             * Call succeeds with 0 bytes read
             */
            return 0;
        }

        if ( flags & MSG_DONTWAIT ) {
            /* See step 3 */
        }

        if ( flags & MSG_ERRQUEUE ) {
        }

        if ( flags & MSG_OOB ) {
            /* TODO */
            /* spec: This flag requests receipt of out-of-band data that would not be received in the normal data stream.
             * Some protocols place expedited data at the head of the normal data queue, and thus this flag cannot be used
             * with such protocols.
             */
        }

        if ( flags & MSG_PEEK ) {
            /* spec: This flag causes the receive operation to return data from the beginning of the receive queue without removing
             * that data from the queue.
             * Thus, a subsequent receive call will return the same data. */

            /* If the incoming queue is empty, put data in it so it can be peeked. */
            enqueueDynamically(socketState, NETAPI_DSID_PEEK_RECV, NETAPI_DSID_DATA_RECV, len);
        }

        if ( flags & MSG_TRUNC ) {
        }

        if ( flags & MSG_WAITALL ) {
            /* spec: This flag requests that the operation block until the full request is satisfied.
             * However, the call may still return less data than requested if a signal is caught, an error or disconnect occurs, or the next
             * data to be received is of a different type than that returned.
             */

            /* Because the caller might assume that a call with MSG_WAITALL always fills all requested bytes,
             * it is interesting to ignore this flag here, and see if the application
             * uses undefined memory - Guido */
        }

        if ( incomingQueue.Available() ) {
            const size_t queueSize = incomingQueue.Size();
            const size_t readSize = std::min(len, queueSize);

            /* TODO make size dynamic? */
            auto data = incomingQueue.Consume(
                    readSize,
                    /* Advance only if not peeking */
                    flags & MSG_PEEK ? false : true);

            if ( readSize > data.size() ) {
                throw std::runtime_error("Attempted OOB read in NetAPIOverlay::recv. This is a bug.");
            }

            if ( recvCallback != nullptr ) {
                recvCallback(data.data(), readSize);
            }

            /* This condition prevents undefined behavior (memcpy to NULL of 0 bytes)*/
            if ( buf != nullptr && readSize > 0 ) {
                memcpy(buf, data.data(), readSize);
            }

            return (ssize_t)readSize;
        } else {
            const auto numBytesReceived = ds.GetData(NETAPI_DSID_DATA_RECV, buf, len);

            return (ssize_t)numBytesReceived;
        }
    }
}

ssize_t NetAPIOverlay::sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    cb(__FUNCTION__);

    const auto socketState = getSocketState(sockfd);

    /* Step 1. Input validation and scanning */
    {
        checkNullPointer(buf, WARNING_SENDTO_BUF_NULLPTR);
        callMemoryCallback(buf, len, sockfd);

        /* spec: If sendto() is used on a connection-mode (SOCK_STREAM, SOCK_SEQPACKET) socket,
         * the arguments dest_addr and addrlen are ignored */
        if ( socketState->GetType() != SOCK_STREAM && socketState->GetType() != SOCK_SEQPACKET ) {
            callMemoryCallback(dest_addr, addrlen, sockfd);
        } else {
            /* spec:
             * If sendto() is used on a connection-mode (SOCK_STREAM, SOCK_SEQPACKET) socket,
             * the arguments dest_addr and addrlen are ignored (and the error EISCONN may be
             * returned when they are not NULL and 0)
             */
            if ( dest_addr != nullptr ) {
                callWarningCallback(WARNING_SENDTO_DESTADDR_INVALID);
                errno = EISCONN;
                return -1;
            }
            if ( addrlen != 0 ) {
                callWarningCallback(WARNING_SENDTO_ADDRLEN_INVALID);
                errno = EISCONN;
                return -1;
            }
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_SENDTO,
                NETAPI_DSID_FAIL_CHOICE_SENDTO,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        /* Check for invalid flags */
        {
            const static FlagTester flagTester({MSG_CONFIRM, MSG_DONTROUTE, MSG_DONTWAIT, MSG_EOR, MSG_MORE, MSG_NOSIGNAL, MSG_OOB});
            if ( flagTester.IsValid(flags) == false ) {
                callWarningCallback(WARNING_SENDTO_INV_FLAGS);
                /* TODO WRITETEST verify with a test that this is the errno for this situation */
                /* spec: EOPNOTSUPP Some bit in the flags argument is inappropriate for the socket type. */
                errno = EOPNOTSUPP;
                return -1;
            }
        }

        if ( socketState->IsConnected() == false ) {
            /* spec: ENOTCONN The socket is not connected, and no target has been given. */
            /* TODO check if target has been given */
            errno = ENOTCONN;
            return -1;
        }

        if ( socketState->IsWriteDisabled() ) {
            /* TODO WRITETEST */
            return 0;
        }

        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

ssize_t NetAPIOverlay::recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        checkNullPointer(buf, WARNING_RECVFROM_BUF_NULLPTR);
        callMemoryCallback(buf, len, sockfd, true); /* points to potentially uninitialized memory */

        if ( src_addr != nullptr ) {
            callMemoryCallback(addrlen, sizeof(socklen_t), sockfd, true); /* points to potentially uninitialized memory */
            callMemoryCallback(src_addr, *addrlen, sockfd, true); /* points to potentially uninitialized memory */
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_SENDTO,
                NETAPI_DSID_FAIL_CHOICE_SENDTO,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        /* Check for invalid flags */
        {
            const static FlagTester flagTester({MSG_CMSG_CLOEXEC, MSG_DONTWAIT, MSG_ERRQUEUE, MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_WAITALL});
            if ( flagTester.IsValid(flags) == false ) {
                callWarningCallback(WARNING_RECVFROM_INV_FLAGS);
                /* TODO WRITETEST which errno? */
                return -1;
            }
        }

        if ( haveSocket(sockfd) == false ) {
            /* spec: ENOTSOCK The file descriptor sockfd does not refer to a socket. */
            errno = ENOTSOCK;
            return -1;
        }

        const auto socketState = getSocketState(sockfd);
        if ( socketState->IsReadDisabled() ) {
            /* TODO WRITETEST */
            return 0;
        }

        if ( socketState->IsConnectionOriented() && src_addr != nullptr ) {
            /* TODO:
             * 1. Generate a sockaddr
             * 3. store it in 'addr'/'addrlen'
             */
        }

        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

ssize_t NetAPIOverlay::sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        callMemoryCallbackMsghdr(msg, sockfd, false);
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::sendmsg(sockfd, msg, flags);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_SENDMSG,
                NETAPI_DSID_FAIL_CHOICE_SENDMSG,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        /* Check for invalid flags */
        {
            const static FlagTester flagTester({MSG_CONFIRM, MSG_DONTROUTE, MSG_DONTWAIT, MSG_EOR, MSG_MORE, MSG_NOSIGNAL, MSG_OOB});
            if ( flagTester.IsValid(flags) == false ) {
                callWarningCallback(WARNING_SENDMSG_INV_FLAGS);
                /* TODO WRITETEST verify with a test that this is the errno for this situation */
                /* spec: EOPNOTSUPP Some bit in the flags argument is inappropriate for the socket type. */
                errno = EOPNOTSUPP;
                return -1;
            }
        }

        if ( haveSocket(sockfd) == false ) {
            /* spec: ENOTSOCK The file descriptor sockfd does not refer to a socket. */
            errno = ENOTSOCK;
            return -1;
        }

        const auto socketState = getSocketState(sockfd);

        switch ( flags ) {
            case    MSG_CONFIRM:
                /* spec:
                 * MSG_CONFIRM (since Linux 2.3.15)
                 *     Tell the link layer that forward progress happened: you got a successful reply from the other side.
                 *     If the link layer doesn't get this it will regularly reprobe the neighbor (e.g., via a unicast ARP).
                 *     Only valid on SOCK_DGRAM and SOCK_RAW sockets and currently implemented only for IPv4 and IPv6.  See arp(7) for details.
                 */

                /* (do nothing) */
                /* TODO WRITETEST error if not DGRAM/RAW, IPV4/IPV6? */
                break;
            case    MSG_DONTROUTE:
                /* spec:
                 * MSG_DONTROUTE
                 *     Don't use a gateway to send out the packet, send to hosts only on directly connected networks.
                 *     This is usually used only by diagnostic or routing programs.  This is defined only for protocol families that route;
                 *     packet sockets don't.
                 */

                /* (do nothing) */
                /* TODO WRITETEST error on packet sockets? */
                break;
            case    MSG_DONTWAIT:
                /* spec:
                 * MSG_DONTWAIT (since Linux 2.2)
                 *     Enables nonblocking operation; if the operation would block, EAGAIN or EWOULDBLOCK is returned.  This provides similar behavior to setting the O_NONBLOCK flag (via the fcntl(2) F_SETFL operation),  but differs
                 *     in that MSG_DONTWAIT is a per-call option, whereas O_NONBLOCK is a setting on the open file description (see open(2)), which will affect all threads in the calling process and as well as other processes that
                 *     hold file descriptors referring to the same open file description.
                 */

                /* TODO */
                break;
            case    MSG_EOR:
                /* spec:
                 * MSG_EOR (since Linux 2.2)
                 *     Terminates a record (when this notion is supported, as for sockets of type SOCK_SEQPACKET).
                 */

                /* TODO */
                break;
            case    MSG_MORE:
                /* spec:
                 * MSG_MORE (since Linux 2.4.4)
                 *     The caller has more data to send.  This flag is used with TCP sockets to obtain the same effect as the TCP_CORK socket option (see tcp(7)), with the difference that this flag can be set on a per-call basis.
                 *     Since Linux 2.6, this flag is also supported for UDP sockets, and informs the kernel to package all of the data sent in calls with this flag set into a single datagram which is transmitted only when a call is
                 *     performed that does not specify this flag.  (See also the UDP_CORK socket option described in udp(7).)
                 */

                /* TODO */
                break;
            case    MSG_NOSIGNAL:
                /* spec:
                 * MSG_NOSIGNAL (since Linux 2.2)
                 *     Don't generate a  SIGPIPE signal if the peer on a stream-oriented socket has closed the connection.  The EPIPE error is still returned.  This provides similar behavior to using sigaction(2) to ignore SIGPIPE,
                 *     but, whereas MSG_NOSIGNAL is a per-call feature, ignoring SIGPIPE sets a process attribute that affects all threads in the process.
                 */

                /* TODO */
                break;
            case    MSG_OOB:
                /* spec:
                 *     MSG_OOB
                 *     Sends out-of-band data on sockets that support this notion (e.g., of type SOCK_STREAM); the underlying protocol must also support out-of-band data.
                 */

                /* TODO */
                if ( socketState->SupportsOOBData() == true ) {
                }
                break;
        }

        if ( socketState->IsWriteDisabled() ) {
            /* TODO WRITETEST */
            return 0;
        }

        size_t totalbytes = 0;
        for (size_t i = 0; i < msg->msg_iovlen; i++) {
            if ( msg->msg_iov[i].iov_len > INT_MAX - totalbytes ) {
                /* TODO WRITETEST errno */
                return -1;
            }
            totalbytes += msg->msg_iov[i].iov_len;
            if ( totalbytes > INT_MAX ) {
                /* TODO WRITETEST errno */
                return -1;
            }
        }

        //const auto numBytesSent = ds.GetInt(0, totalbytes);
        const auto numBytesSent = totalbytes;

        return numBytesSent;
    }

}

ssize_t NetAPIOverlay::recvmsg(int sockfd, struct msghdr *msg, int flags) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        checkNullPointer(msg, WARNING_RECVMSG_BUF_NULLPTR);
        callMemoryCallbackMsghdr(msg, sockfd, true); /* points to potentially uninitialized memory */
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::recvmsg(sockfd, msg, flags);
    }

    /* Step 3. Artificial failure */
    {
        /* Viable errno's:
         * ENOMEM Could not allocate memory for recvmsg().
         */
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_RECVMSG,
                NETAPI_DSID_FAIL_CHOICE_RECVMSG,
                {ENOMEM}
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        /* Check for invalid flags */
        {
            const static FlagTester flagTester({MSG_DONTWAIT, MSG_EOR, MSG_ERRQUEUE, MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_WAITALL});
            if ( flagTester.IsValid(flags) == false ) {
                callWarningCallback(WARNING_RECVMSG_INV_FLAGS);
                /* TODO WRITETEST verify with a test that this is the errno for this situation */
                /* spec: EINVAL Invalid argument passed. */
                errno = EINVAL;
                return -1;
            }
        }

        if ( msg->msg_iovlen < 1 ) {
            /* TODO throw ? return -1 ? */
            abort();
        }

        if ( haveSocket(sockfd) == false ) {
            /* spec: ENOTSOCK The file descriptor sockfd does not refer to a socket. */
            errno = ENOTSOCK;
            return -1;
        }

        const auto socketState = getSocketState(sockfd);
        if ( socketState->IsReadDisabled() ) {
            /* TODO WRITETEST */
            return 0;
        }

        ssize_t numBytesReceived = 0;
        for (size_t i = 0; i < msg->msg_iovlen; i++) {
            memset(msg->msg_iov[i].iov_base, 0, msg->msg_iov[i].iov_len);
            ds.GetData(NETAPI_DSID_DATA_RECVMSG, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
            /* TODO overflow/too much data? */
            numBytesReceived += msg->msg_iov[i].iov_len;
        }

        msg->msg_flags = MSG_EOR;
        return (ssize_t)ds.GetInt(NETAPI_DSID_NUMBYTES_RECVMSG, 0, numBytesReceived);
    }
}

int NetAPIOverlay::getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        checkNullPointer(addr, WARNING_GETSOCKNAME_ADDR_NULLPTR);
        checkNullPointer(addrlen, WARNING_GETSOCKNAME_ADDRLEN_NULLPTR);
        callMemoryCallback(addrlen, sizeof(socklen_t), sockfd);
        callMemoryCallback(addr, *addrlen, sockfd, true); /* points to potentially uninitialized memory */
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::getsockname(sockfd, addr, addrlen);
    }

    /* Step 3. Artificial failure */
    {
        /* Viable errno's:
         * ENOBUFS Insufficient resources were available in the system to perform the operation.
         */
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_GETSOCKNAME,
                NETAPI_DSID_FAIL_CHOICE_GETSOCKNAME,
                {ENOBUFS}
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        getSocketState(sockfd)->WriteSocketName(addr, addrlen);

        return 0;
    }
}

int NetAPIOverlay::getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        callMemoryCallback(addrlen, sizeof(socklen_t), sockfd);
        callMemoryCallback(addr, *addrlen, sockfd, true); /* points to potentially uninitialized memory */
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::getpeername(sockfd, addr, addrlen);
    }

    /* Step 3. Artificial failure */
    {
        /* Viable errno's:
         * ENOBUFS Insufficient resources were available in the system to perform the operation.
         */
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_GETPEERNAME,
                NETAPI_DSID_FAIL_CHOICE_GETPEERNAME,
                {ENOBUFS}
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        if ( haveDescriptor(sockfd) == false ) {
            /* spec: EBADF The argument sockfd is not a valid descriptor. */
            errno = EBADF;
            return -1;
        }

        if ( isSocket(sockfd) == false ) {
            /* spec: ENOTSOCK The file descriptor sockfd does not refer to a socket. */
            errno = ENOTSOCK;
            return -1;
        }

        auto socketState = getSocketState(sockfd);

        /* spec: ENOTCONN The socket is not connected. */
        if ( socketState->IsConnected() == false ) {
            errno = ENOTCONN;
            return -1;
        }

        /* spec: The addrlen argument should be initialized to indicate the amount of space pointed to by addr.
         * On return it contains the actual size of the name returned (in bytes).  The name is truncated if the
         * buffer provided is too small. The returned address is truncated if the buffer provided is too small;
         * in this case, addrlen will return a value greater than was supplied to the call.
         */
        {
            if ( addr != nullptr ) {
                socketState->WritePeerName(addr, addrlen);
            }
        }

        return 0;
    }
}

int NetAPIOverlay::sockatmark(int sockfd) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    /* (none) */

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::sockatmark(sockfd);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_SOCKATMARK,
                NETAPI_DSID_FAIL_CHOICE_SOCKATMARK,
                {} /* No viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

int NetAPIOverlay::isfdtype(int fd, int fdtype) {
    cb(__FUNCTION__);

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(fd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::isfdtype(fd, fdtype);
    }

    /* Step 3. Artificial failure */
    {
        /* Viable errno's:
         *
         * EIO An I/O error occurred.
         */
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_ISFDTYPE,
                NETAPI_DSID_FAIL_CHOICE_ISFDTYPE,
                {EIO}
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

int NetAPIOverlay::close(int fd) {
    cb(__FUNCTION__);

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(fd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::close(fd);
    }

    /* Step 3. Artificial failure */
    {
        /* Viable errno's:
         *
         * EIO An I/O error occurred.
         */
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_CLOSE,
                NETAPI_DSID_FAIL_CHOICE_CLOSE,
                {EIO}
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        DescriptorState* descriptorState = nullptr;

        bool ebadfd = false;
        if ( haveDescriptor(fd) == false ) {
            ebadfd = true;
        } else {
            descriptorState = getDescriptorState(fd);
            if ( descriptorState->IsConnected() == false ) {
                ebadfd = true;
            }
        }

        if ( ebadfd == true ) {
            /* spec: EBADF fd isn't a valid open file descriptor. */
            errno = EBADF;
            callWarningCallback(WARNING_CLOSE_BAD_FD);
            return -1;
        }

        descriptorState->SetDisconnected();

        return 0;
    }
}

int NetAPIOverlay::dup(int oldfd) {
    cb(__FUNCTION__);

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(oldfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::dup(oldfd);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_DUP,
                NETAPI_DSID_FAIL_CHOICE_DUP,
                {} /* No viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        if ( haveDescriptor(oldfd) == true ) {
            /* spec: EBADF oldfd isn't an open file descriptor. */
            errno = EBADF;
            callWarningCallback(WARNING_DUP_BAD_FD);
            return -1;
        }

        /* TODO untested */
        auto descriptorState = getDescriptorState(oldfd);

        auto descriptorLink = new DescriptorLink(getNewFd(), descriptorState);

        return descriptorLink->GetFd();
    }
}

int NetAPIOverlay::dup2(int oldfd, int newfd) {
    cb(__FUNCTION__);

    bool newFdNegative = false;
    /* Step 1. Input validation and scanning */
    {
        if ( newfd < 0 ) {
            callWarningCallback(WARNING_DUP2_NEWFD_NEGATIVE);
            newFdNegative = true;
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(oldfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::dup2(oldfd, newfd);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_DUP2,
                NETAPI_DSID_FAIL_CHOICE_DUP2,
                {} /* No viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        if ( newFdNegative == true ) {
            /* spec:
             * EBADF newfd is out of the allowed range for file descriptors (see the discussion of RLIMIT_NOFILE in getrlimit(2)).
             */
            errno = EBADF;
            return -1;
        }

        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

int NetAPIOverlay::dup3(int oldfd, int newfd, int flags) {
    cb(__FUNCTION__);

    bool newFdNegative = false;
    /* Step 1. Input validation and scanning */
    {
        if ( newfd < 0 ) {
            callWarningCallback(WARNING_DUP2_NEWFD_NEGATIVE);
            newFdNegative = true;
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(oldfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::dup3(oldfd, newfd, flags);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_DUP3,
                NETAPI_DSID_FAIL_CHOICE_DUP3,
                {} /* No viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        /* Check for invalid flags */
        {
            const static FlagTester flagTester({O_CLOEXEC});
            if ( flagTester.IsValid(flags) == false ) {
                callWarningCallback(WARNING_DUP3_INV_FLAGS);
                /* spec: EINVAL (dup3()) flags contain an invalid value. */
                errno = EINVAL;
                return -1;
            }
        }

        if ( newFdNegative == true ) {
            /* spec:
             * EBADF newfd is out of the allowed range for file descriptors (see the discussion of RLIMIT_NOFILE in getrlimit(2)).
             */
            errno = EBADF;
            return -1;
        }

        switch ( flags ) {
            case    O_CLOEXEC:
                /* TODO */
                break;
        }

        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

int NetAPIOverlay::epoll_ctl(int epfd, int op, int fd, struct epoll_event* event) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        /* spec: Applications that need to be portable to kernels before 2.6.9 should specify a non-null pointer in event. */
        checkNullPointer(event, WARNING_EPOLL_CTL_EVENT_NULLPTR);

        callMemoryCallbackEpollEvent(event, op, epfd, true); /* points to potentially uninitialized memory */

        /* TODO WRITETEST behavior if op is invalid */
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(epfd) == false && isOverlayDescriptor(fd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::epoll_ctl(epfd, op, fd, event);
    }

    /* Step 3. Artificial failure */
    {
        /* Viable errno's:
         *
         * ENOMEM There was insufficient memory to handle the requested op control operation.
         * ENOSPC The limit imposed by /proc/sys/fs/epoll/max_user_watches was encountered while trying
         * to register (EPOLL_CTL_ADD) a new file descriptor on an epoll instance.
         */
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_EPOLL_CTL,
                NETAPI_DSID_FAIL_CHOICE_EPOLL_CTL,
                {ENOMEM, ENOSPC}
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        if ( epfd == fd ) {
            /* spec: EINVAL [...] fd is the same as epfd [...] */
            callWarningCallback(WARNING_EPOLL_CTL_BAD_FD);
            errno = EINVAL;
            return -1;
        }

        if ( haveDescriptor(epfd) == true && isEpoll(epfd) == false ) {
            /* spec: EINVAL epfd is not an epoll file descriptor [...] */
            callWarningCallback(WARNING_EPOLL_CTL_BAD_FD);
            errno = EINVAL;
            return -1;
        }

        if ( haveDescriptor(epfd) == false || haveDescriptor(fd) == false ) {
            /* TODO deal with a native 'fd' */
            return 0; /* XXX */
            /* spec: EBADF epfd or fd is not a valid file descriptor. */
            callWarningCallback(WARNING_EPOLL_CTL_BAD_FD);
            errno = EBADF;
            return -1;
        }

        /* TODO enable when enabling AddDisconnectCallback below. auto descriptorState = getDescriptorState(fd); */
        auto epollState = getEpollState(epfd);

        switch ( op ) {
            case    EPOLL_CTL_ADD:
                /* spec: Register the target file descriptor fd on the epoll instance referred
                 * to by the file descriptor epfd and associate the event event with the
                 * internal file linked to fd.
                 */
                if ( epollState->HaveFd(fd) == true ) {
                    callWarningCallback(WARNING_EPOLL_CTL_FD_DUPLICATION);
                    /* spec: EEXIST op was EPOLL_CTL_ADD, and the supplied file descriptor fd is already registered with this epoll instance. */
                    errno = EEXIST;
                    return -1;
                }
                /* TODO descriptorState->AddDisconnectCallback(epollState->DelFd); */
                epollState->AddFd(fd, event->data);
                break;
            case    EPOLL_CTL_MOD:
                /* spec: Change the event event associated with the target file descriptor fd. */
                if ( epollState->HaveFd(fd) == false ) {
                    callWarningCallback(WARNING_EPOLL_CTL_NONEXISTENT_FD);
                    /* ENOENT op was EPOLL_CTL_MOD or EPOLL_CTL_DEL, and fd is not registered with this epoll instance. */
                    errno = ENOENT;
                    return -1;
                }
                epollState->SetData(fd, event->data);
                break;
            case    EPOLL_CTL_DEL:
                /* spec: Remove (deregister) the target file descriptor fd from the epoll instance
                 * referred to by epfd.  The event is ignored and can be NULL (but see BUGS below).
                 */
                if ( epollState->HaveFd(fd) == false ) {
                    callWarningCallback(WARNING_EPOLL_CTL_NONEXISTENT_FD);
                    /* ENOENT op was EPOLL_CTL_MOD or EPOLL_CTL_DEL, and fd is not registered with this epoll instance. */
                    errno = ENOENT;
                    return -1;
                }
                epollState->DelFd(fd);
                break;
            default:
                /* spec: EINVAL [...] the requested operation op is not supported by this interface. */
                errno = EINVAL;
                return -1;
        }

        return 0;
    }
}

int NetAPIOverlay::epoll_pwait(int epfd, struct epoll_event* events, int maxevents, int timeout, const sigset_t* sigmask) {
    cb(__FUNCTION__);

    bool invalidMaxEvents = false;
    bool invalidTimeout = false;

    /* Step 1. Input validation and scanning */
    {
        /* spec: The maxevents argument must be greater than zero. */
        if ( maxevents <= 0 ) {
            callWarningCallback(WARNING_EPOLL_PWAIT_MAXEVENTS);
            invalidMaxEvents = true;
        }

        if ( timeout < 0 && timeout != -1 ) {
             /* spec: Specifying a timeout of -1 causes epoll_wait() to block indefinitely
              * Hence other negative values are incorrect */
            invalidTimeout = true;
        }

        checkNullPointer(events, WARNING_EPOLL_PWAIT_EVENTS_NULLPTR);

        /* Not affected by invalid maxevents */
        for (int i = 0; i < maxevents; i++) {
            callMemoryCallbackEpollEvent(events + i, sizeof(struct epoll_event), epfd, true); /* points to potentially uninitialized memory */
        }

        if ( sigmask != nullptr ) {
            callMemoryCallback(sigmask, sizeof(sigset_t), -1);
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(epfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::epoll_pwait(epfd, events, maxevents, timeout, sigmask);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_EPOLL_PWAIT,
                NETAPI_DSID_FAIL_CHOICE_EPOLL_PWAIT,
                {} /* No viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        if ( invalidMaxEvents == true ) {
            /* spec: EINVAL epfd is not an epoll file descriptor, or maxevents is less than or equal to zero. */
            errno = EINVAL;
            return -1;
        }

        if ( invalidTimeout == true ) {
            /* TODO WRITETEST use test to determine correct behavior */
        }

        /* spec: [..] while specifying a timeout equal to zero cause epoll_wait() to return immediately,
         * even if no events are available */
        if ( timeout == 0 ) {
            return 0;
        }

        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

int NetAPIOverlay::epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout) {
    cb(__FUNCTION__);
    return 0; /* XXX */

    bool invalidMaxEvents = false;

    /* Step 1. Input validation and scanning */
    {
        /* spec: The maxevents argument must be greater than zero. */
        if ( maxevents <= 0 ) {
            callWarningCallback(WARNING_EPOLL_WAIT_MAXEVENTS);
            invalidMaxEvents = true;
        }

        checkNullPointer(events, WARNING_EPOLL_WAIT_EVENTS_NULLPTR);

        /* Not affected by invalid ( <= 0 ) maxevents */
        for (int i = 0; i < maxevents; i++) {
            callMemoryCallbackEpollEvent(events + i, sizeof(struct epoll_event), epfd, true); /* points to potentially uninitialized memory */
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(epfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::epoll_wait(epfd, events, maxevents, timeout);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_EPOLL_WAIT,
                NETAPI_DSID_FAIL_CHOICE_EPOLL_WAIT,
                {} /* No viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        if ( haveDescriptor(epfd) == false ) {
            /* spec: EBADF  epfd is not a valid file descriptor. */
            errno = EBADF;
            return -1;
        }

        if ( isEpoll(epfd) || invalidMaxEvents == true ) {
            /* spec: EINVAL epfd is not an epoll file descriptor, or maxevents is less than or equal to zero. */
            errno = EINVAL;
            return -1;
        }

        const auto epollState = getEpollState(epfd); 

        int numDescriptorsWithEvent = 0;
        epollState->ForEach([&](const int curFd) {
                /* For each descriptor, check if reading, writing is possible, is it closed, etc */
                const auto socketState = getSocketState(curFd);

                /* TODO only if connected ? */
                const bool haveSocketData = haveSocketDataOrEnqueue(socketState, NETAPI_DSID_NUMBYTES_EPOLL_WAIT, NETAPI_DSID_PEEK_EPOLL_WAIT, NETAPI_DSID_DATA_EPOLL_WAIT, 4096);

                auto data = getEpollState(epfd)->GetData(curFd);

                events->events = 0;

                if (
                        socketState->IsConnected() &&
                        !socketState->IsReadDisabled() &&
                        haveSocketData ) {
                    events->events |= EPOLLIN; /* spec: The associated file is available for read(2) operations. */
                }

                if (
                        socketState->IsConnected() &&
                        !socketState->IsReadDisabled() ) {
                    events->events |= EPOLLOUT; /* spec: The associated file is available for write(2) operations. */
                }

                /* TODO other flags */
                events->data = data;
                numDescriptorsWithEvent++;
        });
        /* TODO wait for timeout */
        return numDescriptorsWithEvent;
    }
}

int NetAPIOverlay::fcntl(int fd, int cmd, ...) {
    cb(__FUNCTION__);

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(fd) == false ) {
        cb_delegate(__FUNCTION__);
        va_list args;
        va_start(args, cmd);
        int ret = NetAPI::fcntl(fd, cmd, args);
        va_end(args);
        return ret;
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_FCNTL,
                NETAPI_DSID_FAIL_CHOICE_FCNTL,
                {} /* No viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        switch ( cmd ) {
            case F_GETFL:
                {
                    const auto socketState = getSocketState(fd);
                    /* spec: Get the file access mode and the file status flags; arg is ignored. */

                    /* spec (return value): F_GETFL  Value of file status flags. */
                    return socketState->GetFlags();
                }
                break;
            case F_SETFL:
                {
                    const auto socketState = getSocketState(fd);
                    va_list args;
                    va_start(args, cmd);
                    const int flags = va_arg(args, int);
                    va_end(args);
                    socketState->SetFlags(flags);
                }
                return 0;
            default:
                /* TODO */
                unimplemented(__FUNCTION__);
                return -1;
        }
    }
}

int NetAPIOverlay::ioctl(int fd, unsigned long request, char* argp) {
    cb(__FUNCTION__);

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(fd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::ioctl(fd, request, argp);
    }

    /* Step 3. Artificial failure */
    {
        /* TODO not always returns -1 on failure:
         * spec: A few ioctl() requests use the return value as an output parameter and return a nonnegative value on success.
         */
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_IOCTL,
                NETAPI_DSID_FAIL_CHOICE_IOCTL,
                {} /* No viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        const auto socketState = getSocketState(fd);
        switch ( request ) {
            case    FIONREAD:
                *((int*)argp) = (int)(socketState->GetQueue(SocketState::QUEUE_INCOMING).Size());
                return 0;
        }
        return 0;
        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

int NetAPIOverlay::poll(struct pollfd* fds, nfds_t nfds, int timeout) {
    (void)timeout; /* TODO use variable */
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        checkNullPointer(fds, WARNING_POLL_FDS_NULLPTR);
        callMemoryCallback(fds, sizeof(struct pollfd) * nfds, -1);
    }

    /* Step 3. Artificial failure */
    {
        /* Viable errno's:
         *
         * ENOMEM There was no space to allocate file descriptor tables.
         */
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_POLL,
                NETAPI_DSID_FAIL_CHOICE_POLL,
                {ENOMEM}
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
    /*
     * The bits that may be set/returned in events and revents are defined in <poll.h>:
     *
     * POLLIN There is data to read.
     *
     * POLLPRI There is urgent data to read (e.g., out-of-band data on TCP socket; pseudoterminal master
     * in packet mode has seen state change in slave).
     *
     * POLLOUT Writing is now possible, though a write larger that the available space in a socket or pipe
     * will still block (unless O_NONBLOCK is set).
     *
     * POLLRDHUP (since Linux 2.6.17) Stream socket peer closed connection, or shut down writing half of connection.
     * The _GNU_SOURCE feature test macro must be defined (before including any header files) in order to obtain this definition.
     *
     * POLLERR Error condition (only returned in revents; ignored in events).
     *
     * POLLHUP Hang up (only returned in revents; ignored in events).
     * Note that when reading from a channel such as a pipe or a stream socket, this event merely indicates that the peer
     * closed its end of the channel.
     * Subsequent reads from the channel will return 0 (end of file) only after all outstanding data in the channel has been consumed.
     *
     * POLLNVAL Invalid request: fd not open (only returned in revents; ignored in events).
     *
     * POLLRDNORM Equivalent to POLLIN.
     *
     * POLLRDBAND Priority band data can be read (generally unused on Linux).
     *
     * POLLWRNORM Equivalent to POLLOUT.
     *
     * POLLWRBAND Priority data may be written.

            POLLIN        0x0001
            POLLPRI       0x0002
            POLLOUT       0x0004
            POLLERR       0x0008
            POLLHUP       0x0010
            POLLNVAL      0x0020
            POLLRDNORM    0x0040
            POLLRDBAND    0x0080
            POLLWRNORM    0x0100
            POLLWRBAND    0x0200
            POLLMSG       0x0400
            POLLREMOVE    0x1000
            POLLRDHUP     0x2000
    */
        /* TODO check for wrong bits in fds->events */

        int numNonzeroRevents = 0;
        for (size_t i = 0; i < nfds; i++) {
            uint8_t pollFlags = 0;
            struct pollfd* cur = &(fds[i]);
            const int ev_POLLIN = (cur->events & POLLIN) | (cur->events & POLLRDNORM);
            const int ev_POLLOUT = (cur->events & POLLOUT) | (cur->events & POLLWRNORM);
            /* TODO delegate non-overlay descriptors ? */
            const int curfd = cur->fd;
            bool error = false;

            if (
                    (cur->events & POLLPRI) ||
                    (cur->events & POLLRDBAND) ||
                    (cur->events & POLLWRBAND) ) {
                //printf("Warning: unsupported events flag set in poll\n");
            }

            if ( haveSocket(curfd) == false ) {
                printf("unsupported\n"); /* TODO revents = POLLNVAL, goto next ? WRITETEST */
                abort();
                return -1;
            }

            const auto socketState = getSocketState(curfd);

            cur->revents = 0;

            if ( socketState->IsConnected() == false ) {
                /* spec: POLLNVAL Invalid request: fd not open (only returned in revents; ignored in events). */
                cur->revents |= POLLNVAL;
                error = true;
            }

            if ( error == true ) {
                goto next;
            }

            if ( ev_POLLIN ) {
                /* spec: POLLIN There is data to read. */

                /* TODO socketState->IsReadDisabled()? */

                /* The following call may or may not put some data in the queue (depends on the output of the DataSource) */
                const bool haveSocketData = haveSocketDataOrEnqueue(socketState, NETAPI_DSID_NUMBYTES_POLL, NETAPI_DSID_PEEK_POLL, NETAPI_DSID_DATA_POLL, 4096);

                if ( haveSocketData == true ) {
                    /* There is data in the queue for this socket */
                    cur->revents |= ev_POLLIN;
                }
            }

            /* Get some data to determine which flags in revents to set */
            ds.GetDataExact(NETAPI_DSID_POLLFLAGS_POLL, &pollFlags, sizeof(pollFlags));

            if ( ev_POLLOUT && pollFlags & 1 ) {
                /* TODO socketState->IsWriteDisabled()? */
                cur->revents |= ev_POLLOUT;
            }

            if ( !(pollFlags & 2) ) {
                if ( ev_POLLIN ) {
                    /* By indicating waiting incoming data where there is none,
                     * the application will perform a recv() that will fail, thereby terminating
                     * the connection */
                    cur->revents |= ev_POLLIN;
                }
                //cur->revents |= POLLHUP;
            }

next:
            if ( cur->revents != 0 ) {
                numNonzeroRevents++;
            }
        }

        /* spec:
         * On success, a positive number is returned; this is the number of structures which have nonzero revents fields (in other words, those descriptors with events or errors reported). A value of 0 indicates that the call
         * timed out and no file descriptors were ready. On error, -1 is returned, and errno is set appropriately.
         */

        return numNonzeroRevents;
    }
}

int NetAPIOverlay::ppoll(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p, const sigset_t* sigmask) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        checkNullPointer(fds, WARNING_PPOLL_FDS_NULLPTR);
        callMemoryCallback(fds, sizeof(struct pollfd) * nfds, -1);
        if ( tmo_p != nullptr ) {
            callMemoryCallback(tmo_p, sizeof(struct timespec), -1);
        }
        if ( sigmask != nullptr ) {
            callMemoryCallback(sigmask, sizeof(sigset_t), -1);
        }
    }

    /* TODO check socket */

    /* Step 3. Artificial failure */
    {
        /* Viable errno's:
         *
         * ENOMEM There was no space to allocate file descriptor tables.
         */
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_PPOLL,
                NETAPI_DSID_FAIL_CHOICE_PPOLL,
                {ENOMEM}
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

int NetAPIOverlay::pselect(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timespec* timeout, const sigset_t* sigmask) {
    cb(__FUNCTION__);

    bool nfdsNegative = false;

    /* Step 1. Input validation and scanning */
    {
        if ( nfds < 0 ) {
            callWarningCallback(WARNING_PSELECT_NFDS_NEGATIVE);
            nfdsNegative = true;
        }
        /* TODO callMemoryCallback */
        if ( timeout != nullptr ) {
            callMemoryCallback(timeout, sizeof(struct timespec), -1);
        }

        if ( sigmask != nullptr ) {
            callMemoryCallback(sigmask, sizeof(sigset_t), -1);
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(nfds) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_PSELECT,
                NETAPI_DSID_FAIL_CHOICE_PSELECT,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        if ( nfdsNegative == true ) {
            /* spec: EINVAL nfds is negative */
            errno = EINVAL;
            return -1;
        }

        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

int NetAPIOverlay::recvmmsg(int sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags, struct timespec* timeout) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        for (size_t i = 0; i < vlen; i++) {
            callMemoryCallbackMMsghdr(msgvec + i, sockfd, true); /* points to potentially uninitialized memory */
        }

        if ( timeout != nullptr ) {
            callMemoryCallback(timeout, sizeof(struct timespec), -1);
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::recvmmsg(sockfd, msgvec, vlen, flags, timeout);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_RECVMMSG,
                NETAPI_DSID_FAIL_CHOICE_RECVMMSG,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        const auto socketState = getSocketState(sockfd);
        if ( socketState->IsReadDisabled() ) {
            /* TODO WRITETEST */
            return 0;
        }
        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

int NetAPIOverlay::select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout) {
    cb(__FUNCTION__);

    bool nfdsNegative = false;
    /* Step 1. Input validation and scanning */
    {
        if ( nfds < 0 ) {
            callWarningCallback(WARNING_SELECT_NFDS_NEGATIVE);
            nfdsNegative = true;
        }

        if ( timeout != nullptr ) {
            callMemoryCallback(timeout, sizeof(struct timeval), -1);
        }

        /* TODO callMemoryCallback on fd_sets */
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(nfds) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::select(nfds, readfds, writefds, exceptfds, timeout);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_SELECT,
                NETAPI_DSID_FAIL_CHOICE_SELECT,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        if ( nfdsNegative == true ) {
            /* spec: EINVAL nfds is negative */
            errno = EINVAL;
            return -1;
        }
        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

int NetAPIOverlay::sendmmsg(int sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        for (size_t i = 0; i < vlen; i++) {
            callMemoryCallbackMMsghdr(msgvec + i, sockfd, false);
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(sockfd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::sendmmsg(sockfd, msgvec, vlen, flags);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_SENDMSG,
                NETAPI_DSID_FAIL_CHOICE_SENDMSG,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        /* Check for invalid flags */
        {
            const static FlagTester flagTester({MSG_CONFIRM, MSG_DONTROUTE, MSG_DONTWAIT, MSG_EOR, MSG_MORE, MSG_NOSIGNAL, MSG_OOB});
            if ( flagTester.IsValid(flags) == false ) {
                callWarningCallback(WARNING_SENDMMSG_INV_FLAGS);
                /* TODO WRITETEST which errno?
                 * spec: Errors are as for sendmsg(2).  An error is returned only if no datagrams could be sent.
                 */
                return -1;
            }
        }

        /* spec: The value specified in vlen is capped to UIO_MAXIOV (1024). */
        vlen &= 1023;

        const auto socketState = getSocketState(sockfd);
        if ( socketState->IsWriteDisabled() ) {
            /* TODO WRITETEST */
            return 0;
        }

        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

ssize_t NetAPIOverlay::read(int fd, void* buf, size_t count) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        callMemoryCallback(buf, count, fd, true); /* points to potentially uninitialized memory */
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(fd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::read(fd, buf, count);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_READ,
                NETAPI_DSID_FAIL_CHOICE_READ,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        const auto socketState = getSocketState(fd);
        if ( socketState->IsReadDisabled() ) {
            /* TODO WRITETEST */
            return 0;
        }
        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

ssize_t NetAPIOverlay::readv(int fd, const struct iovec* iov, int iovcnt) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        checkNullPointer(iov, WARNING_READV_IOV_NULLPTR);
        /* TODO callMemoryCallback */
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(fd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::readv(fd, iov, iovcnt);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_READV,
                NETAPI_DSID_FAIL_CHOICE_READV,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        if ( iovcnt < 0 ) {
            /* spec: EINVAL The vector count iovcnt is less than zero or greater than the permitted maximum.
             * TODO: WRITETEST what is the permitted maximum ? */
            callWarningCallback(WARNING_READV_IOVCNT_INVALID);
            errno = EINVAL;
            return -1;
        }

        const auto socketState = getSocketState(fd);
        if ( socketState->IsReadDisabled() ) {
            /* TODO WRITETEST */
            return 0;
        }
        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

ssize_t NetAPIOverlay::sendfile(int out_fd, int in_fd, off_t* offset, size_t count) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        if ( offset != nullptr ) {
            callMemoryCallback(offset, sizeof(off_t), out_fd, false, in_fd);
        }
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(out_fd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::sendfile(out_fd, in_fd, offset, count);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_SENDFILE,
                NETAPI_DSID_FAIL_CHOICE_SENDFILE,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        const auto socketStateOut = getSocketState(out_fd);
        const auto socketStateIn = getSocketState(in_fd);

        if ( socketStateOut->IsWriteDisabled() ) {
            /* TODO WRITETEST */
            return 0;
        }

        if ( socketStateIn->IsReadDisabled() ) {
            /* TODO WRITETEST */
            return 0;
        }

        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

ssize_t NetAPIOverlay::write(int fd, const void* buf, size_t count) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        checkNullPointer(buf, WARNING_WRITE_BUF_NULLPTR);
        callMemoryCallback(buf, count, fd);
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(fd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::write(fd, buf, count);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_WRITE,
                NETAPI_DSID_FAIL_CHOICE_WRITE,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        const auto socketState = getSocketState(fd);
        if ( socketState->IsWriteDisabled() ) {
            /* TODO WRITETEST */
            return 0;
        }

        const auto numBytesSent = ds.GetInt(NETAPI_DSID_NUMBYTES_WRITE, 0, count);

        return numBytesSent;
    }
}

ssize_t NetAPIOverlay::writev(int fd, const struct iovec* iov, int iovcnt) {
    cb(__FUNCTION__);

    /* Step 1. Input validation and scanning */
    {
        checkNullPointer(iov, WARNING_WRITEV_IOV_NULLPTR);
        /* TODO callMemoryCallback */
    }

    /* Step 2. Delegation */
    if ( isOverlayDescriptor(fd) == false ) {
        cb_delegate(__FUNCTION__);
        return NetAPI::writev(fd, iov, iovcnt);
    }

    /* Step 3. Artificial failure */
    {
        ArtificialFailure artificialFailure(ds,
                failState,
                NETAPI_DSID_FAIL_WRITEV,
                NETAPI_DSID_FAIL_CHOICE_WRITEV,
                {} /* no viable errno's */
                );
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        if ( iovcnt < 0 ) {
            /* spec: EINVAL The vector count iovcnt is less than zero or greater than the permitted maximum.
             * TODO: WRITETEST what is the permitted maximum ? */
            callWarningCallback(WARNING_WRITEV_IOVCNT_INVALID);
            errno = EINVAL;
            return -1;
        }

        const auto socketState = getSocketState(fd);
        if ( socketState->IsWriteDisabled() ) {
            /* TODO WRITETEST */
            return 0;
        }

        unimplemented(__FUNCTION__);
        return -1;

        /* TODO */
    }
}

int NetAPIOverlay::epoll_create_work(const int size, const int flags, const bool is_epoll_create1, ArtificialFailure& artificialFailure) {
    (void)is_epoll_create1; /* TODO use variable */

    bool invalidSize = false;
    /* Step 1. Input validation and scanning */
    {
        if ( size <= 0 ) {
            /* TODO only epoll_create, or epoll_create1 too ? */
            /* spec: the size argument is ignored, but must be greater than zero. */
            callWarningCallback(WARNING_EPOLL_CREATE_SIZE_INVALID);
            invalidSize = true;
        }
    }

    /* Step 2. Delegation */
    /* (not applicable) */

    /* Step 3. Artificial failure */
    {
        if ( artificialFailure.GetFailure() == true ) {
            return -1;
        }
    }

    /* Step 4. State mutation, output generation */
    {
        if ( invalidSize == true ) {
            /* EINVAL size is not positive. */
            errno = EINVAL;
            return -1;
        }

        auto epollState = new EpollState(getNewFd());

        /* Check for invalid flags */
        {
            const static FlagTester flagTester({EPOLL_CLOEXEC});
            if ( flagTester.IsValid(flags) == false ) {
                /* spec: EINVAL (epoll_create1()) Invalid value specified in flags. */
                callWarningCallback(WARNING_EPOLL_CREATE1_INV_FLAGS);
                errno = EINVAL;
                return -1;
            }
        }

        switch ( flags ) {
            case    EPOLL_CLOEXEC:
                epollState->SetCloseOnExec();
                break;
        }

        /* An epoll descriptor cannot be connected as such, but it needs to be in
         * this state in order to be closed with close() */
        epollState->SetConnected();

        addDescriptorState(epollState);
        return epollState->GetFd();
    }
}

int NetAPIOverlay::epoll_create(int size) {
    cb(__FUNCTION__);

    /* Viable errno's:
     * EMFILE The per-user limit on the number of epoll instances imposed by /proc/sys/fs/epoll/max_user_instances was encountered.  See epoll(7) for further details.
     * EMFILE The per-process limit on the number of open file descriptors has been reached.
     * ENFILE The system-wide limit on the total number of open files has been reached.
     * ENOMEM There was insufficient memory to create the kernel object.
     */
    ArtificialFailure artificialFailure(ds,
            failState,
            NETAPI_DSID_FAIL_EPOLL_CREATE,
            NETAPI_DSID_FAIL_CHOICE_EPOLL_CREATE,
            {EMFILE, ENFILE, ENOMEM}
            );

    return epoll_create_work(size, 0, false, artificialFailure);
}

int NetAPIOverlay::epoll_create1(int flags) {
    cb(__FUNCTION__);

    /* Viable errno's:
     * EMFILE The per-user limit on the number of epoll instances imposed by /proc/sys/fs/epoll/max_user_instances was encountered.  See epoll(7) for further details.
     * EMFILE The per-process limit on the number of open file descriptors has been reached.
     * ENFILE The system-wide limit on the total number of open files has been reached.
     * ENOMEM There was insufficient memory to create the kernel object.
     */
    ArtificialFailure artificialFailure(ds,
            failState,
            NETAPI_DSID_FAIL_EPOLL_CREATE1,
            NETAPI_DSID_FAIL_CHOICE_EPOLL_CREATE1,
            {EMFILE, ENFILE, ENOMEM}
            );

    return epoll_create_work(1, flags, true, artificialFailure);
}

} /* namespace netapi */
