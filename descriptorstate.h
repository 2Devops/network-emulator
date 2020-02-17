#pragma once

#include "netapi.h"
#include "constants.h"
#include "datasource.h"
#include "peer.h"
#include <vector>
#include <set>
#include <map>

namespace netapi {

class DescriptorState {
    public:
        typedef void (*disconnect_cb_t)(const int fd);
    private:
        bool connected = false;
        std::set<disconnect_cb_t> disconnectCallbacks;
    public:
        int GetFd(void) const;
        typedef enum {
            DESC_TYPE_SOCKET,
            DESC_TYPE_EPOLL,
            DESC_TYPE_LINK,
        } descriptor_type_t;
        bool IsDescriptorType(const descriptor_type_t _descriptorType) const;
        virtual ~DescriptorState(void) { };
        bool IsConnected(void) const;
        void SetConnected(void);
        void SetDisconnected(void);
        void AddDisconnectCallback(const disconnect_cb_t disconnectCallback);
    protected:
        DescriptorState(const int _fd, const descriptor_type_t _descriptorType);
        int fd = -1;
        const descriptor_type_t descriptorType;
};

class DescriptorLink : public DescriptorState {
    private:
        DescriptorState* link;
    public:
        DescriptorLink(const int fd, DescriptorState* _link);
        ~DescriptorLink(void);
        DescriptorState* ResolveLink(void) const;
};

class SocketState : public DescriptorState {
    private:
        int domain = -1;
        int type = -1;
        int protocol = 0;
        bool read_disabled = false;
        bool write_disabled = false;
        bool nonblocking = false;
        bool close_on_exec = false;
        bool listening = false;
        bool bound = false;

        class Name {
            public:
                void SetName(const void* _addr, const socklen_t addrlen);
                bool GenerateName(DataSource& ds, const std::vector<AddressConstraint> constraints);
                const std::vector<uint8_t>& GetName(void) const;
            private:
                std::vector<uint8_t> addr;
                bool addrSet = false;
        } socketName, peerName;

        class Queue {
            private:
                std::vector<uint8_t> queue;
            public:
                bool Available(void) const;
                size_t Size(void) const;
                const std::vector<uint8_t>& Get(void) const;
                void Enqueue(const std::vector<uint8_t>& data);
                std::vector<uint8_t> Consume(const size_t num, const bool doAdvance);
                size_t GetMaxSize(void) const;
        } incomingQueue, oobQueue;

        void writeName(const std::vector<uint8_t>& name, struct sockaddr* addr, socklen_t* addrlen) const;
    public:
        SocketState(const int _sockfd, const int _domain, const int _type, const int _protocol);
        ~SocketState(void);
        void SetSocketName(const void* addr, const socklen_t addrlen);
        const std::vector<uint8_t>& GetSocketName(void) const;
        void WriteSocketName(struct sockaddr* addr, socklen_t* addrlen) const;
        void SetPeerName(const void* addr, const socklen_t addrlen);
        const std::vector<uint8_t>& GetPeerName(void) const;
        void WritePeerName(struct sockaddr* addr, socklen_t* addrlen) const;
        int GetDomain(void) const;
        int GetType(void) const;
        int GetProtocol(void) const;
        bool IsBound(void) const;
        bool IsCloseOnExec(void) const;
        bool IsListening(void) const;
        bool IsNonBlocking(void) const;
        bool IsReadDisabled(void) const;
        bool IsWriteDisabled(void) const;
        bool IsConnectionOriented(void) const;
        bool SupportsOOBData(void) const;

        void SetListening(void);
        void SetBound(void);
        void SetNonBlocking(void);
        void SetBlocking(void);
        void SetCloseOnExec(void);
        void DisableRead(void);
        void DisableWrite(void);
        void EnableRead(void);
        void EnableWrite(void);

        typedef enum {
            QUEUE_INCOMING,
            QUEUE_OOB,
        } queue_type_t;

        Queue& GetQueue(const queue_type_t _type);
        int GetFlags(void) const;
        void SetFlags(const int flags);
};

class EpollState : public DescriptorState {
    private:
        bool close_on_exec = false;
        std::set<int> fds;
        std::map<int, epoll_data_t> fd_to_data;
    public:
        EpollState(const int _fd);
        ~EpollState(void);

        void AddFd(const int _fd, const epoll_data_t data);
        void SetData(const int _fd, const epoll_data_t data);
        epoll_data_t GetData(const int _fd) const;
        bool HaveFd(const int _fd) const;
        void DelFd(const int _fd);
        size_t NumFds(void) const;

        template <class Callback> void ForEach(Callback CB) const
        {
            for ( const auto& fd : fds ) {
                CB(fd);
            }
        }


        bool IsCloseOnExec(void) const;

        void SetCloseOnExec(void);
};

} /* namespace netapi */
