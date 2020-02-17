#include "descriptorstate.h"
#include <string.h>
#include <fcntl.h>

namespace netapi {

/* class DescriptorState */

DescriptorState::DescriptorState(const int _fd, const descriptor_type_t _descriptorType) :
    fd(_fd), descriptorType(_descriptorType) {
}

int DescriptorState::GetFd(void) const {
    return fd;
}

bool DescriptorState::IsDescriptorType(const descriptor_type_t _descriptorType) const {
    return descriptorType == _descriptorType;
}

bool DescriptorState::IsConnected(void) const {
    return connected;
}

void DescriptorState::SetConnected(void) {
    connected = true;
}

void DescriptorState::SetDisconnected(void) {
    if ( connected == true ) {
        for (const auto& cb : disconnectCallbacks ) {
            cb(GetFd());
        }
    }

    connected = false;
}

void DescriptorState::AddDisconnectCallback(const disconnect_cb_t disconnectCallback) {
    disconnectCallbacks.insert(disconnectCallback);
}

/* class DescriptorLink */

DescriptorLink::DescriptorLink(const int _fd, DescriptorState* _link) :
            DescriptorState(_fd, DescriptorState::DESC_TYPE_LINK), link(_link) {
}

DescriptorLink::~DescriptorLink(void) {
}

DescriptorState* DescriptorLink::ResolveLink(void) const {
    size_t chainLength = 0;

    DescriptorState* curDescriptorState = link;

    while ( curDescriptorState->IsDescriptorType(DescriptorState::DESC_TYPE_LINK) ) {
        if ( chainLength >= constMaxDescriptorChainLength ) {
            throw std::runtime_error("Chain length too long when resolving descriptor links");
        }
        curDescriptorState = dynamic_cast<DescriptorLink*>(curDescriptorState)->ResolveLink();
        chainLength++;
    }

    return curDescriptorState;
}

/* class SocketState */

SocketState::SocketState(const int _sockfd, const int _domain, const int _type, const int _protocol) :
            DescriptorState(_sockfd, DescriptorState::DESC_TYPE_SOCKET),
            domain(_domain), type(_type), protocol(_protocol) {
}

SocketState::~SocketState(void) {
}

void SocketState::writeName(const std::vector<uint8_t>& name, struct sockaddr* addr, socklen_t* addrlen) const {

    if ( name.size() > *addrlen ) {
        /* spec:  The returned address is truncated if the buffer provided is too small;
         * in this case, addrlen will return a value greater than was supplied to the call.
         */
        *addrlen = name.size();
    }

    const size_t _addrlen = *addrlen;
    *addrlen = std::max(name.size(), _addrlen);
    memcpy(addr, name.data(), std::min(name.size(), _addrlen));
}

void SocketState::SetSocketName(const void* addr, const socklen_t addrlen) {
    socketName.SetName(addr, addrlen);
}

void SocketState::SetPeerName(const void* addr, const socklen_t addrlen) {
    peerName.SetName(addr, addrlen);
}

const std::vector<uint8_t>& SocketState::GetSocketName(void) const {
    return socketName.GetName();
}

void SocketState::WriteSocketName(struct sockaddr* addr, socklen_t* addrlen) const {
    writeName(GetSocketName(), addr, addrlen);
}

const std::vector<uint8_t>& SocketState::GetPeerName(void) const {
    return peerName.GetName();
}

void SocketState::WritePeerName(struct sockaddr* addr, socklen_t* addrlen) const {
    writeName(GetPeerName(), addr, addrlen);
}

int SocketState::GetDomain(void) const {
    return domain;
}

int SocketState::GetType(void) const {
    return type;
}

int SocketState::GetProtocol(void) const {
    return protocol;
}

bool SocketState::IsNonBlocking(void) const {
    return nonblocking;
}

bool SocketState::IsCloseOnExec(void) const {
    return close_on_exec;
}

bool SocketState::IsListening(void) const {
    return listening;
}

bool SocketState::IsBound(void) const {
    return bound;
}

bool SocketState::IsReadDisabled(void) const {
    return read_disabled;
}

bool SocketState::IsWriteDisabled(void) const {
    return write_disabled;
}

bool SocketState::IsConnectionOriented(void) const {
    /* TODO */
    return true;
}

bool SocketState::SupportsOOBData(void) const {
    /* TODO this OK? */
    return type == SOCK_STREAM;
}

void SocketState::SetListening(void) {
    listening = true;
}

void SocketState::SetBound(void) {
    bound = true;
}

void SocketState::SetNonBlocking(void) {
    nonblocking = true;
}

void SocketState::SetBlocking(void) {
    nonblocking = false;
}

void SocketState::SetCloseOnExec(void) {
    close_on_exec = true;
}

void SocketState::DisableRead(void) {
    read_disabled = true;
}

void SocketState::DisableWrite(void) {
    write_disabled = true;
}

void SocketState::EnableRead(void) {
    read_disabled = false;
}

void SocketState::EnableWrite(void) {
    write_disabled = false;
}

SocketState::Queue& SocketState::GetQueue(const queue_type_t _type) {
    switch ( _type ) {
        case    QUEUE_INCOMING:
            return incomingQueue;
        case    QUEUE_OOB:
            return oobQueue;
        default:
            throw std::runtime_error("SocketState::GetQueue: Invalid queue type specified");
    }
}

int SocketState::GetFlags(void) const {
    /*
       O_ACCMODE
       O_APPEND
       O_CLOEXEC
       O_CREAT
       O_DIRECT
       O_DIRECTORY
       O_DSYNC
       O_EXCL
       O_LARGEFILE
       O_NOATIME
       O_NOCTTY
       O_NOFOLLOW
       O_NONBLOCK
       O_RDONLY
       O_RDWR
       O_TRUNC
       O_WRONLY
	*/

    int flags = 0;

    if ( !IsReadDisabled() && IsWriteDisabled() ) {
        flags |= O_RDONLY;
    } else if ( IsReadDisabled() && !IsWriteDisabled() ) {
        flags |= O_WRONLY;
    } else if ( !IsReadDisabled() && !IsWriteDisabled() ) {
        flags |= O_RDWR;
    }

    if ( IsNonBlocking() ) {
        flags |= O_NONBLOCK;
    }

    return flags;
}

void SocketState::SetFlags(const int flags) {
    if ( flags & O_RDONLY ) {
        EnableRead();
        DisableWrite();
    } else if ( flags & O_WRONLY ) {
        DisableRead();
        EnableWrite();
    } else if ( flags & O_RDWR ) {
        EnableRead();
        EnableWrite();
    }

    if ( flags & O_NONBLOCK ) {
        SetNonBlocking();
    } else if ( !(flags & O_NONBLOCK) ) {
        SetBlocking();
    } else {
        abort();
    }
}

/* class SocketState::Name */

void SocketState::Name::SetName(const void* _addr, const socklen_t addrlen) {
    if ( addrSet == true ) {
        throw std::runtime_error("SocketState::Setname: addr and/or addrlen pre-initialized");
    }

    if ( addrlen > constMaxNameSize ) {
        throw std::runtime_error("SocketState::Setname: addrlen is unreasonable");
    }

    addr.resize(addrlen);
    memcpy(addr.data(), _addr, addrlen);

    addrSet = true;
}

bool SocketState::Name::GenerateName(DataSource& ds, const std::vector<AddressConstraint> constraints) {
    /* TODO
     * Fill out a struct sockaddr with data source
     * If it doesn't match all constraints, fail (return false)
     * TODO use Peer ?
     */
    addrSet = true;
    return true;
}

const std::vector<uint8_t>& SocketState::Name::GetName(void) const {
    if ( addrSet == false ) {
        throw std::runtime_error("GetName() called on unset Name");
    }
    return addr;
}

/* class SocketState::Queue */

bool SocketState::Queue::Available(void) const {
    return queue.size() != 0;
}

size_t SocketState::Queue::Size(void) const {
    return queue.size();
}

const std::vector<uint8_t>& SocketState::Queue::Get(void) const {
    return queue;
}

void SocketState::Queue::Enqueue(const std::vector<uint8_t>& data) {
    if ( Available() ) {
        throw std::runtime_error("Attempted to enqueue multiple buffers");
    }

    if ( data.size() > GetMaxSize() ) {
        throw std::runtime_error("Attempted to enqueue overly large buffer");
    }

    queue = data;
}

std::vector<uint8_t> SocketState::Queue::Consume(const size_t num, const bool doAdvance) {
    if ( num > queue.size() ) {
        throw std::runtime_error("Queue overread");
    }

    const auto startIter = queue.begin();
    const auto endIter = queue.begin() + num;

    /* TODO untested */
    const std::vector<uint8_t> ret(startIter, endIter);

    if ( doAdvance == true ) {
        queue.erase(startIter, endIter);
    }

    return ret;
}

size_t SocketState::Queue::GetMaxSize(void) const {
    return constMaxQueueSize;
}

/* class EpollState */

EpollState::EpollState(const int _fd) :
            DescriptorState(_fd, DescriptorState::DESC_TYPE_EPOLL) {
}

EpollState::~EpollState(void) {
}

void EpollState::AddFd(const int _fd, const epoll_data_t data) {
    fds.insert(_fd);
    SetData(_fd, data);
}

void EpollState::SetData(const int _fd, const epoll_data_t data) {
    fd_to_data[_fd] = data;
}

epoll_data_t EpollState::GetData(const int _fd) const {
    if ( fd_to_data.find(_fd) == fd_to_data.end() ) {
        throw std::runtime_error("Requested file descriptor not found in EpollState::GetData()");
    }
    return fd_to_data.at(_fd);
}

bool EpollState::HaveFd(const int _fd) const {
    return fds.count(_fd) >= 1;
}

void EpollState::DelFd(const int _fd) {
    if ( fds.find(_fd) == fds.end() ) {
        throw std::runtime_error("Requested file descriptor not found in EpollState::DelFd()");
    }
    fds.erase(_fd);
}

size_t EpollState::NumFds(void) const {
    return fds.size();
}

bool EpollState::IsCloseOnExec(void) const {
    return close_on_exec;
}

void EpollState::SetCloseOnExec(void) {
    close_on_exec = true;
}

} /* namespace netapi */
