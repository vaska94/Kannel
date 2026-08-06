/* ==================================================================== 
 * The Kannel Software License, Version 1.0 
 * 
 * Copyright (c) 2001-2018 Kannel Group  
 * Copyright (c) 1998-2001 WapIT Ltd.   
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 * 
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 * 
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in 
 *    the documentation and/or other materials provided with the 
 *    distribution. 
 * 
 * 3. The end-user documentation included with the redistribution, 
 *    if any, must include the following acknowledgment: 
 *       "This product includes software developed by the 
 *        Kannel Group (http://www.kannel.org/)." 
 *    Alternately, this acknowledgment may appear in the software itself, 
 *    if and wherever such third-party acknowledgments normally appear. 
 * 
 * 4. The names "Kannel" and "Kannel Group" must not be used to 
 *    endorse or promote products derived from this software without 
 *    prior written permission. For written permission, please  
 *    contact org@kannel.org. 
 * 
 * 5. Products derived from this software may not be called "Kannel", 
 *    nor may "Kannel" appear in their name, without prior written 
 *    permission of the Kannel Group. 
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED.  IN NO EVENT SHALL THE KANNEL GROUP OR ITS CONTRIBUTORS 
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,  
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT  
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR  
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,  
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE  
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,  
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 * ==================================================================== 
 * 
 * This software consists of voluntary contributions made by many 
 * individuals on behalf of the Kannel Group.  For more information on  
 * the Kannel Group, please see <http://www.kannel.org/>. 
 * 
 * Portions of this software are based upon software originally written at  
 * WapIT Ltd., Helsinki, Finland for the Kannel project.  
 */ 

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

#include "gwlib.h"


static Octstr *official_name = NULL;
static Octstr *official_ip = NULL;

/*
 * Whether IPv6 may be used at all. Off by default: turning a listener
 * dual-stack and resolving AF_UNSPEC are visible behaviour changes for an
 * IPv4-only deployment, so they wait for the `ipv6' core-group setting.
 * See socket_enable_ipv6().
 */
static int ipv6_enabled = 0;


void socket_enable_ipv6(int enable)
{
    ipv6_enabled = enable ? 1 : 0;
    debug("gwlib.socket", 0, "IPv6 %s.", ipv6_enabled ? "enabled" : "disabled");
}


int socket_ipv6_enabled(void)
{
    return ipv6_enabled;
}


/*
 * Address family to ask the resolver for. AF_UNSPEC lets it return both
 * families; AF_INET keeps a disabled build indistinguishable from before.
 */
static int wanted_family(void)
{
    return ipv6_enabled ? AF_UNSPEC : AF_INET;
}

/*
 * FreeBSD is not happy with our approach of allocating a sockaddr
 * and then filling in the fields.  It has private fields that need
 * to be initialized to 0.  This structure is used for that.
 */
static const struct sockaddr_in empty_sockaddr_in;

#ifndef UDP_PACKET_MAX_SIZE
#define UDP_PACKET_MAX_SIZE (64*1024)
#endif


/*
 * Bind the local end of an outgoing socket. `family' must match the family of
 * the socket, because a source address only makes sense within one family.
 * Returns 0 on success, -1 on failure.
 */
static int bind_local_end(int s, int family, int our_port,
                          const char *source_addr)
{
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[NI_MAXSERV];
    const char *node;
    int reuse = 1, rc, bound = -1;

    snprintf(portstr, sizeof(portstr), "%d", our_port);

    node = (source_addr != NULL && strcmp(source_addr, "*") != 0)
           ? source_addr : NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    rc = getaddrinfo(node, portstr, &hints, &res);
    if (rc != 0) {
        error(0, "getaddrinfo for source address <%s> failed: %s",
              node ? node : "*", gai_strerror(rc));
        return -1;
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &reuse,
                   sizeof(reuse)) == -1) {
        error(errno, "setsockopt failed before bind");
        freeaddrinfo(res);
        return -1;
    }

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        if (bind(s, ai->ai_addr, ai->ai_addrlen) == 0) {
            bound = 0;
            break;
        }
    }
    if (bound == -1)
        error(errno, "bind to local port %d failed", our_port);

    freeaddrinfo(res);
    return bound;
}


/*
 * Resolve and bind a listening socket within one address family. Returns the
 * descriptor, or -1 if no address in that family could be bound.
 */
static int bind_listener(const char *node, const char *portstr, int family,
                        int wildcard)
{
    struct addrinfo hints, *res = NULL, *ai;
    int s = -1, rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    rc = getaddrinfo(node, portstr, &hints, &res);
    if (rc != 0) {
        /* Only informational: the caller may still have another family to try. */
        debug("gwlib.socket", 0, "getaddrinfo for <%s> family %d failed: %s",
              node != NULL ? node : "*", family, gai_strerror(rc));
        return -1;
    }

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        int reuse = 1;

        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == -1) {
            /* e.g. EAFNOSUPPORT when IPv6 is disabled at runtime. */
            debug("gwlib.socket", 0, "socket() for family %d failed: %s",
                  ai->ai_family, strerror(errno));
            continue;
        }

        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &reuse,
                       sizeof(reuse)) == -1) {
            error(errno, "setsockopt failed for server address");
            goto next;
        }

#if defined(IPV6_V6ONLY) && defined(AF_INET6)
        if (ai->ai_family == AF_INET6) {
            int off = 0;
            if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &off,
                           sizeof(off)) == -1 && wildcard) {
                /*
                 * A wildcard bind exists to serve both families from one
                 * socket, so failing to clear IPV6_V6ONLY must not be
                 * cosmetic: some platforms forbid dual-stack sockets outright
                 * (OpenBSD), and carrying on would silently drop IPv4
                 * service. Give up on this candidate so the caller can fall
                 * back to AF_INET.
                 */
                warning(errno, "cannot clear IPV6_V6ONLY on a wildcard "
                        "listener; falling back to IPv4");
                goto next;
            }
        }
#endif

        if (bind(s, ai->ai_addr, ai->ai_addrlen) == -1) {
            error(errno, "bind failed");
            goto next;
        }

        if (listen(s, 10) == -1) {
            error(errno, "listen failed");
            goto next;
        }

        break;

    next:
        (void) close(s);
        s = -1;
    }

    freeaddrinfo(res);
    return s;
}


int make_server_socket(int port, const char *interface_name)
{
    char portstr[NI_MAXSERV];
    int s;

    snprintf(portstr, sizeof(portstr), "%d", port);

    if (interface_name == NULL || strcmp(interface_name, "*") == 0) {
        /*
         * With IPv6 enabled, prefer the IPv6 wildcard with IPV6_V6ONLY cleared
         * so a single socket serves both families, and fall back to IPv4 if
         * that does not work at all - IPv6 may be compiled in but disabled at
         * runtime, in which case resolution succeeds while socket(), bind() or
         * the IPV6_V6ONLY setsockopt does not.
         *
         * With IPv6 disabled this is an AF_INET bind, exactly as before.
         */
        s = -1;
#ifdef AF_INET6
        if (ipv6_enabled)
            s = bind_listener(NULL, portstr, AF_INET6, 1);
#endif
        if (s == -1) {
            if (ipv6_enabled)
                info(0, "No IPv6 listener on port %d, using IPv4 only.", port);
            s = bind_listener(NULL, portstr, AF_INET, 1);
        }
    } else {
        /*
         * A named interface binds ONE socket, so when the name resolves in both
         * families a choice has to be made. Try IPv4 first: before getaddrinfo()
         * was used here the lookup went through gethostbyname(), which returned
         * the IPv4 address, so preferring IPv6 would silently stop serving IPv4
         * clients on configurations such as
         *     admin-interface = "localhost"
         * An IPv6-only name still yields an IPv6 listener, and an explicit
         * literal binds exactly what was asked for. To serve both families on a
         * named address, use the wildcard and filter with the *-allow-ip rules.
         */
        s = bind_listener(interface_name, portstr, AF_INET, 0);
        if (s == -1 && ipv6_enabled)
            s = bind_listener(interface_name, portstr, AF_INET6, 0);
    }

    if (s == -1)
        error(0, "could not create a listening socket on port %d", port);

    return s;
}


int tcpip_connect_to_server(char *hostname, int port, const char *source_addr)
{

    return tcpip_connect_to_server_with_port(hostname, port, 0, source_addr);
}


int tcpip_connect_to_server_with_port(char *hostname, int port, int our_port, const char *source_addr)
{
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[NI_MAXSERV];
    int s = -1, rc, saved_errno = 0;
    int bind_local = (our_port > 0 ||
                      (source_addr != NULL && strcmp(source_addr, "*") != 0));

    snprintf(portstr, sizeof(portstr), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = wanted_family();
    hints.ai_socktype = SOCK_STREAM;
    /*
     * AI_ADDRCONFIG is deliberately NOT set. It would suppress candidates in
     * families the host has no configured address for, which sounds right, but
     * glibc ignores loopback when making that judgement: on a host whose only
     * IPv6 address is ::1, getaddrinfo("::1", AI_ADDRCONFIG) fails outright with
     * EAI_ADDRFAMILY. That would break an `smsc host = ::1' or a dlr-url naming
     * an IPv6 literal. The log noise it was meant to avoid is instead handled by
     * demoting per-candidate failures below while candidates remain.
     */

    rc = getaddrinfo(hostname, portstr, &hints, &res);
    if (rc != 0) {
        error(0, "getaddrinfo for `%s' failed: %s", hostname, gai_strerror(rc));
        goto error;
    }

    /*
     * The address family is only known once the name has been resolved, and
     * consecutive candidates may belong to different families, so the socket
     * has to be created per candidate rather than once up front.
     */
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        Octstr *ip;

        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == -1) {
            /*
             * A family this host cannot do is expected while walking candidates
             * from AF_UNSPEC and another may still work, so it is not an error.
             * Anything else is - descriptor exhaustion above all, which used to
             * be reported here and would otherwise reach the operator only as
             * the generic "error connecting to server", with errno lost.
             */
            if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
                debug("gwlib.socket", 0, "socket() for family %d: %s",
                      ai->ai_family, strerror(errno));
            else
                error(errno, "Couldn't create new socket.");
            continue;
        }

        if (bind_local &&
            bind_local_end(s, ai->ai_family, our_port, source_addr) == -1) {
            (void) close(s);
            s = -1;
            continue;
        }

        ip = gw_sockaddr_to_octstr(ai->ai_addr);
        debug("gwlib.socket", 0, "Connecting to <%s>", octstr_get_cstr(ip));

        rc = connect(s, ai->ai_addr, ai->ai_addrlen);
        saved_errno = errno;            /* before anything else can clobber it */
        if (rc == -1) {
            /*
             * Not an error yet if another candidate remains - a dual-stack
             * destination legitimately fails on one family and works on the
             * other. The caller gets one error() below if all of them fail.
             */
            if (ai->ai_next != NULL)
                warning(saved_errno, "connect to <%s> failed, trying next address",
                        octstr_get_cstr(ip));
            else
                error(saved_errno, "connect to <%s> failed", octstr_get_cstr(ip));
        }
        octstr_destroy(ip);

        if (rc == 0)
            break;

        (void) close(s);
        s = -1;
    }

    freeaddrinfo(res);
    res = NULL;

    if (s == -1)
        goto error;

    return s;

error:
    error(0, "error connecting to server `%s' at port `%d'", hostname, port);
    if (res != NULL)
        freeaddrinfo(res);
    if (s >= 0)
        (void) close(s);
    return -1;
}

int tcpip_connect_nb_to_server(char *hostname, int port, const char *source_addr, int *done)
{
    return tcpip_connect_nb_to_server_with_port(hostname, port, 0, source_addr, done);
}

int tcpip_connect_nb_to_server_with_port(char *hostname, int port, int our_port, const char *source_addr, int *done)
{
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[NI_MAXSERV];
    int s = -1, flags, rc = -1, saved_errno = 0;
    int bind_local = (our_port > 0 ||
                      (source_addr != NULL && strcmp(source_addr, "*") != 0));

    *done = 1;

    snprintf(portstr, sizeof(portstr), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = wanted_family();
    hints.ai_socktype = SOCK_STREAM;
    /*
     * AI_ADDRCONFIG is deliberately NOT set. It would suppress candidates in
     * families the host has no configured address for, which sounds right, but
     * glibc ignores loopback when making that judgement: on a host whose only
     * IPv6 address is ::1, getaddrinfo("::1", AI_ADDRCONFIG) fails outright with
     * EAI_ADDRFAMILY. That would break an `smsc host = ::1' or a dlr-url naming
     * an IPv6 literal. The log noise it was meant to avoid is instead handled by
     * demoting per-candidate failures below while candidates remain.
     */

    rc = getaddrinfo(hostname, portstr, &hints, &res);
    if (rc != 0) {
        error(0, "getaddrinfo for `%s' failed: %s", hostname, gai_strerror(rc));
        goto error;
    }

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        Octstr *ip;

        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == -1) {
            /*
             * A family this host cannot do is expected while walking candidates
             * from AF_UNSPEC and another may still work, so it is not an error.
             * Anything else is - descriptor exhaustion above all, which used to
             * be reported here and would otherwise reach the operator only as
             * the generic "error connecting to server", with errno lost.
             */
            if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
                debug("gwlib.socket", 0, "socket() for family %d: %s",
                      ai->ai_family, strerror(errno));
            else
                error(errno, "Couldn't create new socket.");
            continue;
        }

        if (bind_local &&
            bind_local_end(s, ai->ai_family, our_port, source_addr) == -1) {
            (void) close(s);
            s = -1;
            continue;
        }

        flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);

        ip = gw_sockaddr_to_octstr(ai->ai_addr);
        debug("gwlib.socket", 0, "Connecting nonblocking to <%s>",
              octstr_get_cstr(ip));

        rc = connect(s, ai->ai_addr, ai->ai_addrlen);
        /*
         * Capture errno immediately: freeaddrinfo(), error() and
         * octstr_destroy() below make no promise about preserving it, and a
         * clobbered value would misread a legitimately pending connect as a
         * failure.
         */
        saved_errno = errno;
        if (rc == -1 && saved_errno != EINPROGRESS) {
            if (ai->ai_next != NULL)
                warning(saved_errno, "nonblocking connect to <%s> failed, "
                        "trying next address", octstr_get_cstr(ip));
            else
                error(saved_errno, "nonblocking connect to <%s> failed",
                      octstr_get_cstr(ip));
        }
        octstr_destroy(ip);

        /*
         * NOTE: once a candidate reports EINPROGRESS we have to return it - the
         * caller polls for completion. If that connect then fails
         * asynchronously, the remaining candidates are never tried. On a host
         * whose IPv6 route is black-holed this makes an outbound connection fail
         * where an IPv4-only build would have succeeded; setting `ipv6 = false'
         * in the core group is the remedy. Retrying across the deferred failure
         * needs the candidate list to outlive this call and is left for later.
         */
        if (rc == 0 || saved_errno == EINPROGRESS)
            break;

        (void) close(s);
        s = -1;
    }

    freeaddrinfo(res);
    res = NULL;

    if (s == -1 || (rc == -1 && saved_errno != EINPROGRESS))
        goto error;

    /* May be connected immediatly
     * (if we connecting to localhost for example)
     */
    if (rc == 0) {
        *done = 0;
    }

    return s;

error:
    error(0, "error connecting to server `%s' at port `%d'", hostname, port);
    if (res != NULL)
        freeaddrinfo(res);
    if (s >= 0)
        (void) close(s);
    return -1;
}


int write_to_socket(int socket, char *str)
{
    size_t len;
    int ret;

    len = strlen(str);
    while (len > 0) {
        ret = write(socket, str, len);
        if (ret == -1) {
            if (errno == EAGAIN) continue;
            if (errno == EINTR) continue;
            error(errno, "Writing to socket failed");
            return -1;
        }
        /* ret may be less than len, if the writing was interrupted
           by a signal. */
        len -= ret;
        str += ret;
    }
    return 0;
}


int socket_set_blocking(int fd, int blocking)
{
    int flags, newflags;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        error(errno, "cannot get flags for fd %d", fd);
        return -1;
    }

    if (blocking)
        newflags = flags & ~O_NONBLOCK;
    else
        newflags = flags | O_NONBLOCK;

    if (newflags != flags) {
        if (fcntl(fd, F_SETFL, newflags) < 0) {
            error(errno, "cannot set flags for fd %d", fd);
            return -1;
        }
    }

    return 0;
}


int socket_set_nodelay(int fd, int on)
{
    int rc;

    rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof (on));
    if (rc == -1)
        error(errno, "Unable set TCP_NODELAY(%d)", on);

    return rc;
}


int read_available(int fd, long wait_usec)
{
    fd_set rf;
    struct timeval to;
    int ret;
    div_t waits;

    gw_assert(fd >= 0);

    FD_ZERO(&rf);
    FD_SET(fd, &rf);
    waits = div(wait_usec, 1000000);
    to.tv_sec = waits.quot;
    to.tv_usec = waits.rem;
retry:
    ret = select(fd + 1, &rf, NULL, NULL, &to);
    if (ret > 0 && FD_ISSET(fd, &rf))
        return 1;
    if (ret < 0) {
        /* In most select() implementations, to will now contain the
         * remaining time rather than the original time.  That is exactly
         * what we want when retrying after an interrupt. */
        switch (errno) {
            /*The first two entries here are OK*/
        case EINTR:
            goto retry;
        case EAGAIN:
            return 1;
            /* We are now sucking mud, figure things out here
             * as much as possible before it gets lost under
             * layers of abstraction.  */
        case EBADF:
            if (!FD_ISSET(fd, &rf)) {
                warning(0, "Tried to select on fd %d, not in the set!\n", fd);
            } else {
                warning(0, "Tried to select on invalid fd %d!\n", fd);
            }
            break;
        case EINVAL:
            /* Catchall "It didn't work" error, lets apply
             * some tests and see if we can catch it. */

            /* First up, try invalid timeout*/
            if (to.tv_sec > 10000000)
                warning(0, "Wait more than three years for a select?\n");
            if (to.tv_usec > 1000000)
                warning(0, "There are only 1000000 usec in a second...\n");
            break;


        }
        return -1; 	/* some error */
    }
    return 0;
}



int udp_client_socket(void)
{
    int s;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s == -1) {
        error(errno, "Couldn't create a UDP socket");
        return -1;
    }

    return s;
}


int udp_bind(int port, const char *source_addr)
{
    int s;
    struct sockaddr_in sa;
    struct hostent hostinfo;
    char *buff = NULL;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s == -1) {
        error(errno, "Couldn't create a UDP socket");
        return -1;
    }

    sa = empty_sockaddr_in;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (strcmp(source_addr, "*") == 0)
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    else {
        if (gw_gethostbyname(&hostinfo, source_addr, &buff) == -1) {
            error(errno, "gethostbyname failed");
            gw_free(buff);
            return -1;
        }
        sa.sin_addr = *(struct in_addr *) hostinfo.h_addr;
    }

    if (bind(s, (struct sockaddr *) &sa, (int) sizeof(sa)) == -1) {
        error(errno, "Couldn't bind a UDP socket to port %d", port);
        (void) close(s);
        return -1;
    }

    gw_free(buff);

    return s;
}


Octstr *udp_create_address(Octstr *host_or_ip, int port)
{
    struct sockaddr_in sa;
    struct hostent h;
    char *buff = NULL;
    Octstr *ret;

    sa = empty_sockaddr_in;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    if (strcmp(octstr_get_cstr(host_or_ip), "*") == 0) {
        sa.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (gw_gethostbyname(&h, octstr_get_cstr(host_or_ip), &buff) == -1) {
            error(0, "Couldn't find the IP number of `%s'",
                  octstr_get_cstr(host_or_ip));
            gw_free(buff);
            return NULL;
        }
        sa.sin_addr = *(struct in_addr *) h.h_addr;
    }

    ret = octstr_create_from_data((char *) &sa, sizeof(sa));
    gw_free(buff);

    return ret;
}


int udp_get_port(Octstr *addr)
{
    struct sockaddr_in sa;

    gw_assert(octstr_len(addr) == sizeof(sa));
    memcpy(&sa, octstr_get_cstr(addr), sizeof(sa));
    return ntohs(sa.sin_port);
}


Octstr *udp_get_ip(Octstr *addr)
{
    struct sockaddr_in sa;

    gw_assert(octstr_len(addr) == sizeof(sa));
    memcpy(&sa, octstr_get_cstr(addr), sizeof(sa));
    return gw_netaddr_to_octstr(AF_INET, &sa.sin_addr);
}


int udp_sendto(int s, Octstr *datagram, Octstr *addr)
{
    struct sockaddr_in sa;

    gw_assert(octstr_len(addr) == sizeof(sa));
    memcpy(&sa, octstr_get_cstr(addr), sizeof(sa));
    if (sendto(s, octstr_get_cstr(datagram), octstr_len(datagram), 0,
               (struct sockaddr *) &sa, (int) sizeof(sa)) == -1) {
        error(errno, "Couldn't send UDP packet");
        return -1;
    }
    return 0;
}


int udp_recvfrom(int s, Octstr **datagram, Octstr **addr)
{
    return udp_recvfrom_flags(s, datagram, addr, 0);
}


int udp_recvfrom_flags(int s, Octstr **datagram, Octstr **addr, int sockrcvflags)
{
    struct sockaddr_in sa;
    socklen_t salen;
    char *buf;
    int bytes;

    buf = gw_malloc(UDP_PACKET_MAX_SIZE);

    salen = sizeof(sa);
    bytes = recvfrom(s, buf, UDP_PACKET_MAX_SIZE, sockrcvflags, (struct sockaddr *) &sa, &salen);
    if (bytes == -1) {
        if (errno != EAGAIN)
            error(errno, "Couldn't receive UDP packet");
	gw_free(buf);
        return -1;
    }

    *datagram = octstr_create_from_data(buf, bytes);
    *addr = octstr_create_from_data((char *) &sa, salen);

    gw_free(buf);

    return 0;
}


Octstr *host_ip(struct sockaddr_in addr)
{
    return gw_netaddr_to_octstr(AF_INET, &addr.sin_addr);
}


int host_port(struct sockaddr_in addr)
{
    return ntohs(addr.sin_port);
}


Octstr *get_official_name(void)
{
    gw_assert(official_name != NULL);
    return official_name;
}


Octstr *get_official_ip(void)
{
    gw_assert(official_ip != NULL);
    return official_ip;
}


static void setup_official_name(void)
{
    struct utsname u;
    struct addrinfo hints, *res = NULL;
    int rc;

    gw_assert(official_name == NULL);
    if (uname(&u) == -1)
        panic(0, "uname failed - can't happen, unless " GW_NAME " is buggy.");

    /*
     * getaddrinfo rather than gethostbyname, for consistency with the rest of
     * this file.
     *
     * NOTE this runs from socket_init(), i.e. out of gwlib_init(), which is
     * well before the configuration has been read - so socket_enable_ipv6()
     * cannot have been called yet and wanted_family() is necessarily AF_INET
     * here. That is deliberate rather than accidental: resolving the local name
     * differently would change the reported official name and IP, and this is
     * not gated by anything the operator has had a chance to set. The
     * consequence is that on an IPv6-only host the official IP is still
     * reported as 127.0.0.1 in the startup banner, which is where these two
     * values are used.
     */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = wanted_family();
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    rc = getaddrinfo(u.nodename, NULL, &hints, &res);
    if (rc != 0 || res == NULL) {
        error(0, "Can't find out official hostname for this host (%s), "
              "using `%s' instead.", gai_strerror(rc), u.nodename);
        official_name = octstr_create(u.nodename);
        official_ip = octstr_create("127.0.0.1");
    } else {
        official_name = octstr_create(res->ai_canonname != NULL
                                      ? res->ai_canonname : u.nodename);
        official_ip = gw_sockaddr_to_octstr(res->ai_addr);
        if (official_ip == NULL)
            official_ip = octstr_create("127.0.0.1");
    }
    if (res != NULL)
        freeaddrinfo(res);
}


void socket_init(void)
{
    setup_official_name();
}

void socket_shutdown(void)
{
    octstr_destroy(official_name);
    official_name = NULL;
    octstr_destroy(official_ip);
    official_ip = NULL;
}


Octstr *gw_netaddr_to_octstr(int af, void *src)
{
    switch (af) {
    case AF_INET: {
        char straddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, src, straddr, sizeof(straddr));
        return octstr_create(straddr);
    }

#ifdef AF_INET6
    case AF_INET6: {
        char straddr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, src, straddr, sizeof(straddr));
        return octstr_create(straddr);
    }
#endif

    default:
        return NULL;
    }
}


Octstr *gw_sockaddr_to_octstr(const struct sockaddr *sa)
{
    if (sa == NULL)
        return NULL;

    switch (sa->sa_family) {
    case AF_INET:
        return gw_netaddr_to_octstr(AF_INET,
                   (void *) &((const struct sockaddr_in *) sa)->sin_addr);

#ifdef AF_INET6
    case AF_INET6: {
        const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *) sa;

        /*
         * Render IPv4-mapped addresses (::ffff:a.b.c.d) as plain IPv4. On a
         * dual-stack listener every IPv4 peer arrives mapped, and the
         * configuration uses IPv4-style globs for things like box-allow-ip, so
         * without this the mapped form would silently stop matching.
         */
        if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
            struct in_addr v4;
            memcpy(&v4, ((const unsigned char *) &sa6->sin6_addr) + 12,
                   sizeof(v4));
            return gw_netaddr_to_octstr(AF_INET, (void *) &v4);
        }
        return gw_netaddr_to_octstr(AF_INET6, (void *) &sa6->sin6_addr);
    }
#endif

    default:
        /*
         * Never return NULL: the result is handed to boxc_create() and
         * client_create() as the connection's peer address and logged in many
         * places, so a NULL would propagate far from here before crashing.
         * A placeholder cannot match a specific allow pattern, and a
         * deny-everything rule still denies it.
         */
        warning(0, "Cannot describe peer address family %d", (int) sa->sa_family);
        return octstr_create("unknown");
    }
}


int gw_sockaddr_port(const struct sockaddr *sa)
{
    if (sa == NULL)
        return -1;

    switch (sa->sa_family) {
    case AF_INET:
        return ntohs(((const struct sockaddr_in *) sa)->sin_port);
#ifdef AF_INET6
    case AF_INET6:
        return ntohs(((const struct sockaddr_in6 *) sa)->sin6_port);
#endif
    default:
        return -1;
    }
}


int gw_accept(int fd, Octstr **client_addr)
{
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int new_fd;

    if (gwthread_pollfd(fd, POLLIN, -1.0) != POLLIN) {
	debug("gwlib.socket", 0, "gwthread_pollfd interrupted or failed");
	return -1;
    }
    /*
     * sockaddr_storage, not sockaddr_in: a dual-stack listener hands back
     * sockaddr_in6, which would be truncated into the smaller IPv4 struct.
     */
    addrlen = sizeof(addr);
    new_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
    if (new_fd == -1) {
	error(errno, "accept system call failed.");
	return -1;
    }
    *client_addr = gw_sockaddr_to_octstr((struct sockaddr *) &addr);
    debug("test_smsc", 0, "accept() succeeded, client from %s",
	  octstr_get_cstr(*client_addr));
    return new_fd;
}
