#!/usr/bin/env python

from hashlib import sha1

fndecls = [
    ["int", "accept", "int sockfd", "struct sockaddr* addr", "socklen_t* addrlen"],
    ["int", "accept4", "int sockfd", "struct sockaddr* addr", "socklen_t* addrlen", "int flags"],
    ["int", "bind", "int sockfd", "const struct sockaddr* addr", "socklen_t addrlen"],
    ["int", "close", "int fd"],
    ["int", "connect", "int sockfd", "const struct sockaddr* addr", "socklen_t addrlen"],
    ["int", "dup", "int oldfd"],
    ["int", "dup2", "int oldfd", "int newfd"],
    ["int", "dup3", "int oldfd", "int newfd", "int flags"],
    ["int", "epoll_ctl", "int epfd", "int op", "int fd", "struct epoll_event* event"],
    ["int", "epoll_pwait", "int epfd", "struct epoll_event* events", "int maxevents", "int timeout", "const sigset_t* sigmask"],
    ["int", "epoll_wait", "int epfd", "struct epoll_event* events", "int maxevents", "int timeout"],
    ["int", "fcntl", "int fd", "int cmd", "..."],
    ["int", "getpeername", "int sockfd", "struct sockaddr* addr", "socklen_t* addrlen"],
    ["int", "getsockname", "int sockfd", "struct sockaddr* addr", "socklen_t* addrlen"],
    ["int", "getsockopt", "int sockfd", "int level", "int optname", "void* optval", "socklen_t* optlen"],
    ["int", "ioctl", "int fd", "unsigned long request", "char* argp"],
    ["int", "isfdtype", "int fd", "int fdtype"],
    ["int", "listen", "int sockfd", "int backlog"],
    ["int", "poll", "struct pollfd* fds", "nfds_t nfds", "int timeout"],
    ["int", "ppoll", "struct pollfd* fds", "nfds_t nfds", "const struct timespec* tmo_p", "const sigset_t* sigmask"],
    ["int", "pselect", "int nfds", "fd_set* readfds", "fd_set* writefds", "fd_set* exceptfds", "const struct timespec* timeout", "const sigset_t* sigmask"],
    ["int", "recvmmsg", "int sockfd", "struct mmsghdr* msgvec", "unsigned int vlen", "int flags", "struct timespec* timeout"],
    ["int", "select", "int nfds", "fd_set* readfds", "fd_set* writefds", "fd_set* exceptfds", "struct timeval* timeout"],
    ["int", "sendmmsg", "int sockfd", "struct mmsghdr* msgvec", "unsigned int vlen", "int flags"],
    ["int", "setsockopt", "int sockfd", "int level", "int optname", "const void* optval", "socklen_t optlen"],
    ["int", "shutdown", "int sockfd", "int how"],
    ["int", "sockatmark", "int sockfd"],
    ["int", "socket", "int domain", "int type", "int protocol"],
    ["ssize_t", "read", "int fd", "void* buf", "size_t count"],
    ["ssize_t", "readv", "int fd", "const struct iovec* iov", "int iovcnt"],
    ["ssize_t", "recv", "int sockfd", "void* buf", "size_t len", "int flags"],
    ["ssize_t", "recvfrom", "int sockfd", "void* buf", "size_t len", "int flags", "struct sockaddr* src_addr", "socklen_t* addrlen"],
    ["ssize_t", "recvmsg", "int sockfd", "struct msghdr* msg", "int flags"],
    ["ssize_t", "send", "int sockfd", "const void* buf", "size_t len", "int flags"],
    ["ssize_t", "sendfile", "int out_fd", "int in_fd", "off_t* offset", "size_t count"],
    ["ssize_t", "sendmsg", "int sockfd", "const struct msghdr* msg", "int flags"],
    ["ssize_t", "sendto", "int sockfd", "const void* buf", "size_t len", "int flags", "const struct sockaddr* dest_addr", "socklen_t addrlen"],
    ["ssize_t", "write", "int fd", "const void* buf", "size_t count"],
    ["ssize_t", "writev", "int fd", "const struct iovec* iov", "int iovcnt"],
    ['int' ,'epoll_create', 'int size'],
    ['int', 'epoll_create1', 'int flags']
]

tpl_impl = """%s NetAPI::%s(%s) {
    %s
    typedef %s (*orig_fn_type)(%s);
    orig_fn_type origfn = (orig_fn_type)dlsym(RTLD_NEXT, "%s");
    %s ret = origfn(%s);
    %s
    return ret;
}

"""

tpl_decl = """%s %s %s(%s) %s;
"""

tpl_lib_impl = """extern "C" %s %s(%s) {
    %s
    %s ret = getInstance()->%s(%s);
    %s
    return ret;
}

"""

tpl_ds_ids_header = """#pragma once

enum {
"""
tpl_ds_ids_enum = "    NETAPI_DSID_%s_%s = %s,\n"
tpl_ds_ids_footer = """
};"""

netapi_impl_cpp = ""
netapi_method_decl_h = ""
netapioverlay_method_decl_h = ""
netapi_lib_impl_cpp = ""
netapi_ds_ids_h = ""

fn_hashes = []

def getfnhash(s, add):
    global fn_hashes
    h = sha1(s).digest()
    r = ord(h[0])
    r += ord(h[1]) * (2**8)
    r += ord(h[2]) * (2**16)
    r += add * (2**24)
    r_str = "0x" + hex(r)[2:].zfill(8)
    if r_str in fn_hashes:
        print "Error: duplicate function hash"
        exit(1)
    fn_hashes += [ r_str ]
    return r_str

netapi_ds_ids_h = tpl_ds_ids_header
for decl in fndecls:
    rettype = decl[0]
    fnname = decl[1]
    args = decl[2:]

    args_types = []
    args_types_str = []
    args_names = []

    for a in args:
        args_split = a.split(' ')
        if len(args_split) == 1:
            a_types = args_split
        else:
            a_types = args_split[:-1]
        args_types += [ a_types ]
        args_types_str += [ " ".join(a_types) ]
        if args_split[-1] == '...':
            args_names += [ "args" ]
        else:
            args_names += [ args_split[-1] ]

    args_types_fullstr = ", ".join(args_types_str)
    args_names_fullstr = ", ".join(args_names)

    args_str = ", ".join(args)

    if 'args' in args_names:
        header = "va_list va; va_start(va, %s); const int args = va_arg(va, int);" % (args_names[-2])
        footer = "va_end(va);"
    else:
        header = ""
        footer = ""


    netapi_impl_cpp += tpl_impl % (rettype, fnname, args_str, header, rettype, args_types_fullstr, fnname, rettype, args_names_fullstr, footer)
    netapi_method_decl_h += tpl_decl % ("virtual", rettype, fnname, args_str, "")
    netapioverlay_method_decl_h += tpl_decl % ("", rettype, fnname, args_str, "override")
    netapi_lib_impl_cpp += tpl_lib_impl % (rettype, fnname, args_str, header, rettype, fnname, args_names_fullstr, footer)
    netapi_ds_ids_h += tpl_ds_ids_enum % ("FAIL", fnname.upper(), getfnhash(fnname, 0))
    netapi_ds_ids_h += tpl_ds_ids_enum % ("FAIL_CHOICE", fnname.upper(), getfnhash(fnname, 1))
    if fnname in ['send', 'recvmsg', 'write', 'poll', 'epoll_wait']:
        netapi_ds_ids_h += tpl_ds_ids_enum % ("NUMBYTES", fnname.upper(), getfnhash(fnname, 2))
    if fnname in ['recv', 'recvmsg', 'poll', 'epoll_wait']:
        netapi_ds_ids_h += tpl_ds_ids_enum % ("DATA", fnname.upper(), getfnhash(fnname, 3))
    if fnname in ['recv', 'recvfrom', 'recvmsg', 'poll', 'epoll_wait']:
        netapi_ds_ids_h += tpl_ds_ids_enum % ("PEEK", fnname.upper(), getfnhash(fnname, 4))
    if fnname in ['poll']:
        netapi_ds_ids_h += tpl_ds_ids_enum % ("POLLFLAGS", fnname.upper(), getfnhash(fnname, 5))

netapi_ds_ids_h += tpl_ds_ids_footer

with open('netapi_impl.cpp', 'wb') as fp:
    fp.write(netapi_impl_cpp)
with open('netapi_method_decl.h', 'wb') as fp:
    fp.write(netapi_method_decl_h)
with open('netapioverlay_method_decl.h', 'wb') as fp:
    fp.write(netapioverlay_method_decl_h)
with open('netapi_lib_impl.cpp', 'wb') as fp:
    fp.write(netapi_lib_impl_cpp)
with open('netapi_ds_ids.h', 'wb') as fp:
    fp.write(netapi_ds_ids_h)
