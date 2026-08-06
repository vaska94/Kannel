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

/*
 * check_url.c - check URL parsing, in particular bracketed IPv6 literals
 *
 * The colons inside an IPv6 literal are part of the address, so the port
 * separator has to be found after the closing bracket, and the brackets
 * themselves must not reach getaddrinfo() or the Host: header.
 */

#include "gwlib/gwlib.h"


int main(void)
{
    int i;
    static struct {
        char *url;
        char *host;         /* expected host, brackets stripped */
        long port;
        char *path;
    } tab[] = {
        /* IPv4 and hostnames must keep working exactly as before */
        { "http://127.0.0.1/",              "127.0.0.1",   80,   "/" },
        { "http://127.0.0.1:8080/wh",       "127.0.0.1",   8080, "/wh" },
        { "http://example.com/a/b",         "example.com", 80,   "/a/b" },
        { "http://example.com:9090/a",      "example.com", 9090, "/a" },
        { "http://example.com",             "example.com", 80,   "/" },
        /* bracketed IPv6 literals */
        { "http://[::1]/",                  "::1",         80,   "/" },
        { "http://[::1]:18080/wh",          "::1",         18080,"/wh" },
        { "http://[2001:db8::1]:2775/x",    "2001:db8::1", 2775, "/x" },
        { "http://[2001:db8::1]/x",         "2001:db8::1", 80,   "/x" },
        { "http://[fd00::dead:beef]:80/",   "fd00::dead:beef", 80, "/" },
    };

    /*
     * Forms that must be refused rather than silently mangled. The last one
     * would otherwise take a ']' from inside the path.
     */
    static char *bad[] = {
        "http://[::1",
        "http://[]",
        "http://[]:80/",
        "http://[::1/foo]bar",
        /*
         * Trailing garbage after the literal. Without the check these parsed:
         * the first with a host of "[::1]extra", the second with "[::1", which
         * then went out in an unbalanced Host: header, and the third tripped an
         * assertion inside octstr_copy() rather than being refused.
         */
        "http://[::1]extra/foo",
        "http://[::1?foo]bar",
        "http://[::1]@evil.com/",
    };

    /*
     * Emission is the mirror of parsing: the host is kept bare for
     * getaddrinfo(), so anything writing it back into a URL or a Host: header
     * has to re-bracket an IPv6 literal.
     */
    static struct { char *host; char *emitted; } hosts[] = {
        { "example.com",      "example.com" },
        { "127.0.0.1",        "127.0.0.1" },
        { "::1",              "[::1]" },
        { "2001:db8::1",      "[2001:db8::1]" },
        { "fe80::1%eth0",     "[fe80::1%eth0]" },
        { "[::1]",            "[::1]" },      /* already bracketed, left alone */
    };

    gwlib_init();
    log_set_output_level(GW_INFO);

    for (i = 0; (size_t) i < sizeof(tab) / sizeof(tab[0]); ++i) {
        Octstr *url = octstr_create(tab[i].url);
        HTTPURLParse *p = parse_url(url);

        if (p == NULL)
            panic(0, "parse_url failed for <%s>", tab[i].url);
        if (octstr_str_compare(p->host, tab[i].host) != 0)
            panic(0, "parse_url <%s>: host is <%s>, expected <%s>",
                  tab[i].url, octstr_get_cstr(p->host), tab[i].host);
        if (p->port != tab[i].port)
            panic(0, "parse_url <%s>: port is %ld, expected %ld",
                  tab[i].url, p->port, tab[i].port);
        if (octstr_str_compare(p->path, tab[i].path) != 0)
            panic(0, "parse_url <%s>: path is <%s>, expected <%s>",
                  tab[i].url, octstr_get_cstr(p->path), tab[i].path);

        http_urlparse_destroy(p);
        octstr_destroy(url);
    }

    /*
     * Refusing a malformed URL logs an ERROR by design, and run-checks fails a
     * check on any ERROR reaching stderr, so raise the stderr threshold before
     * exercising these. The level is not restored afterwards: logging is
     * asynchronous and the writer thread consults the threshold when it drains
     * the queue, so lowering it again here would let the very messages this is
     * meant to hide through. Nothing below logs, and panic() clears any
     * threshold, so a regression is still loud.
     */
    log_set_output_level(GW_PANIC);
    for (i = 0; (size_t) i < sizeof(bad) / sizeof(bad[0]); ++i) {
        Octstr *url = octstr_create(bad[i]);
        HTTPURLParse *p = parse_url(url);

        if (p != NULL)
            panic(0, "parse_url accepted malformed <%s>, host <%s>",
                  bad[i], octstr_get_cstr(p->host));
        octstr_destroy(url);
    }

    for (i = 0; (size_t) i < sizeof(hosts) / sizeof(hosts[0]); ++i) {
        Octstr *host = octstr_create(hosts[i].host);
        Octstr *got = http_host_for_url(host);

        if (got == NULL)
            panic(0, "http_host_for_url(<%s>) returned NULL", hosts[i].host);
        if (octstr_str_compare(got, hosts[i].emitted) != 0)
            panic(0, "http_host_for_url(<%s>) gave <%s>, expected <%s>",
                  hosts[i].host, octstr_get_cstr(got), hosts[i].emitted);
        octstr_destroy(got);
        octstr_destroy(host);
    }

    if (http_host_for_url(NULL) != NULL)
        panic(0, "http_host_for_url(NULL) must return NULL");

    info(0, "check_url: all cases passed");

    gwlib_shutdown();
    return 0;
}
