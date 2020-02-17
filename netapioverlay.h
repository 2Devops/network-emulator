#pragma once

#include "artificialfailure.h"
#include "datasource.h"
#include "descriptorstate.h"
#include "failstate.h"
#include "artificialfailure.h"
#include "netapi.h"

namespace netapi {

class NetAPIOverlay : public NetAPI {
    private:
        typedef enum {
            WARNING_CONNECT_ADDR_NULLPTR,
            WARNING_DOUBLE_CONNECT,
            WARNING_BIND_ADDR_NULLPTR,
            WARNING_ACCEPT_NOT_LISTENING,
            WARNING_ACCEPT_ADDRLEN_NOT_NULL,
            WARNING_ACCEPT4_NOT_LISTENING,
            WARNING_ACCEPT4_ADDRLEN_NOT_NULL,
            WARNING_ACCEPT4_INV_FLAGS,
            WARNING_SHUTDOWN_INVALID_HOW,
            WARNING_SEND_BUF_NULLPTR,
            WARNING_RECV_BUF_NULLPTR,
            WARNING_RECV_INV_FLAGS,
            WARNING_SEND_INV_FLAGS,
            WARNING_SEND_INV_MSG_CONFIRM,
            WARNING_SENDTO_BUF_NULLPTR,
            WARNING_SENDTO_DESTADDR_INVALID,
            WARNING_SENDTO_ADDRLEN_INVALID,
            WARNING_SENDTO_INV_FLAGS,
            WARNING_RECVFROM_BUF_NULLPTR,
            WARNING_RECVFROM_INV_FLAGS,
            WARNING_SENDMSG_INV_FLAGS,
            WARNING_RECVMSG_BUF_NULLPTR,
            WARNING_RECVMSG_INV_FLAGS,
            WARNING_GETSOCKNAME_ADDR_NULLPTR,
            WARNING_GETSOCKNAME_ADDRLEN_NULLPTR,
            WARNING_LISTEN_BACKLOG_INVALID,
            WARNING_DOUBLE_LISTEN,
            WARNING_LISTEN_UNBOUND,
            WARNING_LISTEN_CONNECTED,
            WARNING_CLOSE_BAD_FD,
            WARNING_DUP_BAD_FD,
            WARNING_DUP2_NEWFD_NEGATIVE,
            WARNING_DUP3_NEWFD_NEGATIVE,
            WARNING_DUP3_INV_FLAGS,
            WARNING_EPOLL_CTL_EVENT_NULLPTR,
            WARNING_EPOLL_CTL_FD_DUPLICATION,
            WARNING_EPOLL_CTL_NONEXISTENT_FD,
            WARNING_EPOLL_CTL_BAD_FD,
            WARNING_EPOLL_PWAIT_EVENTS_NULLPTR,
            WARNING_EPOLL_WAIT_EVENTS_NULLPTR,
            WARNING_POLL_FDS_NULLPTR,
            WARNING_PPOLL_FDS_NULLPTR,
            WARNING_PSELECT_NFDS_NEGATIVE,
            WARNING_SELECT_NFDS_NEGATIVE,
            WARNING_EPOLL_PWAIT_MAXEVENTS,
            WARNING_EPOLL_WAIT_MAXEVENTS,
            WARNING_SENDMMSG_INV_FLAGS,
            WARNING_READV_IOV_NULLPTR,
            WARNING_READV_IOVCNT_INVALID,
            WARNING_WRITE_BUF_NULLPTR,
            WARNING_WRITEV_IOV_NULLPTR,
            WARNING_WRITEV_IOVCNT_INVALID,
            WARNING_EPOLL_CREATE_SIZE_INVALID,
            WARNING_EPOLL_CREATE1_FLAGS_INVALID,
            WARNING_EPOLL_CREATE1_INV_FLAGS,
        } warning_t;

        FailState failState;

        DataSource& ds;
        const size_t maxDescriptors;

        int curSockFd;

        std::map<int, DescriptorState*> descriptorStates;

        bool enqueueDynamically(SocketState* socketState, const datasource_id peek_dsid, const datasource_id recv_dsid, const size_t len);
        bool haveSocketDataOrEnqueue(SocketState* socketState, const datasource_id numbytes_dsid, const datasource_id peek_dsid, const datasource_id recv_dsid, const size_t len);
        int getNewFd(void);
        bool isOverlayDescriptor(const int fd) const;
        bool haveDescriptor(const int fd) const;
        DescriptorState* getDescriptorState(const int fd) const;
        bool isEpoll(const int fd) const;
        bool isSocket(const int fd) const;
        bool haveSocket(const int fd) const;
        bool haveEpoll(const int fd) const;
        SocketState* getSocketState(const int fd) const;
        EpollState* getEpollState(const int fd) const;
        void addDescriptorState(DescriptorState* descriptorState);
        void unimplemented(const std::string methodName) const;
        void cb(const std::string methodName) const;
        void cb_delegate(const std::string methodName) const;
        void callMemoryCallback(const void* data, const size_t size, const int fd, const bool uninitialized = false, const int fd2 = -1) const;
        void callMemoryCallbackMsghdr(const struct msghdr* msg, const int fd, const bool uninitialized) const;
        void callMemoryCallbackMMsghdr(const struct mmsghdr* msg, const int fd, const bool uninitialized) const;
        void callMemoryCallbackEpollEvent(const struct epoll_event* event, const int op, const int epfd, const bool uninitialized) const;
        void callWarningCallback(const warning_t warning) const;
        void checkNullPointer(const void* p, const warning_t warning) const;

    /* Callbacks */
    public:
        typedef void (*recv_cb_t)(uint8_t* data, size_t size);
        typedef void (*function_cb_t)(const std::string methodName);
        typedef void (*memory_cb_t)(const uint8_t* data, size_t size, bool isOverlayDescriptor, bool uninitialized);
        typedef void (*warning_cb_t)(const warning_t warning);
    private:
        recv_cb_t recvCallback = nullptr;
        function_cb_t functionCallback = nullptr;
        memory_cb_t memoryCallback = nullptr;
        warning_cb_t warningCallback = nullptr;

    public:
        void SetRecvCallback(const recv_cb_t callback);
        void SetFunctionCallback(const function_cb_t callback);
        void SetMemoryCallback(const memory_cb_t callback);
        void SetWarningCallback(const warning_cb_t callback);

    /* End of callbacks */

    public:
        NetAPIOverlay(DataSource& dataSource, size_t _maxDescriptors = 1000, int _failProbability = 50);
        ~NetAPIOverlay(void);
        void SetContinueFailing(const bool _continueFailing);


        int accept_work(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags, const bool is_accept4, ArtificialFailure& artificialFailure);
        int epoll_create_work(const int size, const int flags, const bool is_epoll_create1, ArtificialFailure& artificialFailure);

#include "netapioverlay_method_decl.h"
};

} /* namespace netapi */
