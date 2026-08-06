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
 * check_ipcheck.c - check the is_allowed_ip function
 *
 * Lars Wirzenius
 */


#include "gwlib/gwlib.h"


int main(void)
{
    Octstr *ip;
    Octstr *allowed;
    Octstr *denied;
    int result;
    int i;
    static struct {
	int ipv6;			/* value of the `ipv6' core setting */
	char *allowed;
	char *denied;
	char *ip;
	int should_be_allowed;
    } tab[] = {
	{ 0, "127.0.0.1", "", "127.0.0.1", 1 },
	{ 0, "127.0.0.1", "", "127.0.0.2", 1 },
	{ 0, "127.0.0.1", "*.*.*.*", "127.0.0.1", 1 },
	{ 0, "127.0.0.1", "*.*.*.*", "1.2.3.4", 0 },
	{ 0, "127.0.0.1", "127.0.0.*", "1.2.3.4", 1 },
	{ 0, "127.0.0.1", "127.0.0.*", "127.0.0.2", 0 },
	/*
	 * With IPv6 off, matching must be exactly what it always was. These pin
	 * the two rules added below to the enabled case only, so that turning the
	 * feature off cannot change what an existing configuration means.
	 * A bare "*" has never matched a dotted quad - the matcher advances a
	 * wildcard only to the next dot - so a deny list of "*" still denies
	 * nobody here, however surprising that is on its own.
	 */
	{ 0, "", "*", "10.0.0.5", 1 },
	{ 0, "127.0.0.1", "*", "10.0.0.5", 1 },
	{ 0, "::1", "*.*.*.*", "127.0.0.9", 0 },
	/*
	 * Unreachable in practice - with IPv6 off no listener accepts an IPv6
	 * peer, so no ::1 ever reaches here - but pinned to the value the plain
	 * glob matcher produces, which is what this build must keep doing.
	 */
	{ 0, "127.0.0.1", "*.*.*.*", "::1", 1 },
	/*
	 * "*" and "*.*.*.*" mean "any address" in either family. A wildcard
	 * otherwise stops at a dot and an IPv6 address contains none, so without
	 * this a deny-everything rule would let IPv6 peers through once a listener
	 * accepts both families.
	 */
	{ 1, "127.0.0.1;::1", "*.*.*.*", "10.0.0.5", 0 },
	{ 1, "127.0.0.1;::1", "*.*.*.*", "2600:1f16::99", 0 },
	{ 1, "127.0.0.1;::1", "*.*.*.*", "::1", 1 },
	{ 1, "127.0.0.1", "*.*.*.*", "fd00::dead:beef", 0 },
	{ 1, "2600:1f16::1", "*.*.*.*", "2600:1f16::1", 1 },
	/*
	 * A bare "*" is NOT universal, in either direction and in either mode.
	 * It still behaves as it always has under plain globbing: a wildcard runs
	 * up to the next dot, so "*" matches an address with no dots - every IPv6
	 * address - and matches no dotted quad.
	 *
	 * The consequence for a deny list is a pre-existing wart, pinned here
	 * rather than fixed, because correcting it would change IPv4 behaviour and
	 * belongs in its own change.
	 */
	{ 1, "", "*", "2600:1f16::99", 0 },
	{ 1, "", "*", "10.0.0.5", 1 },
	/*
	 * And the reason it must stay non-universal: as an allow-list entry it
	 * would otherwise admit an IPv4 peer that the deny list names explicitly,
	 * purely because IPv6 was switched on.
	 */
	{ 0, "*", "1.2.3.4", "1.2.3.4", 0 },
	{ 1, "*", "1.2.3.4", "1.2.3.4", 0 },
	{ 1, "127.0.0.1", "*", "10.0.0.5", 1 },
	/*
	 * "*.*.*.*" carries no such risk - it already glob-matches every dotted
	 * quad - so it is the one form treated as universal.
	 * A partial wildcard matches no real address, just as before, so it must
	 * not become allow-all either.
	 */
	{ 1, "*.*", "*.*.*.*", "1.2.3.4", 0 },
	{ 1, "*.*.*", "*.*.*.*", "1.2.3.4", 0 },
	{ 1, "*.", "*.*.*.*", "1.2.3.4", 0 },
	/*
	 * A loopback rule in one family covers the other family's loopback: a
	 * dual-stack listener sees a local peer as ::1, which getaddrinfo() returns
	 * first for "localhost", and an existing IPv4-only loopback ACL has to keep
	 * working. Within one family the normal globbing still applies, which the
	 * 127.0.0.* row above pins.
	 */
	{ 1, "127.0.0.1", "*.*.*.*", "::1", 1 },
	{ 1, "::1", "*.*.*.*", "127.0.0.1", 1 },
	{ 1, "127.0.0.1", "*.*.*.*", "2600:1f16::99", 0 },
	{ 1, "127.0.0.1", "*.*.*.*", "10.0.0.5", 0 },
	/*
	 * Matching is textual, not semantic: these spellings are not recognised as
	 * equivalent. Pinned so the behaviour is documented rather than assumed.
	 */
	{ 1, "::1", "*.*.*.*", "0:0:0:0:0:0:0:1", 0 },
	{ 1, "2001:db8::1", "*.*.*.*", "2001:DB8::1", 0 },
	{ 1, "127.0.0.1", "*.*.*.*", "::ffff:127.0.0.1", 0 },
    };
    
    gwlib_init();
    log_set_output_level(GW_INFO);
        
    for (i = 0; (size_t) i < sizeof(tab) / sizeof(tab[0]); ++i) {
	allowed = octstr_imm(tab[i].allowed);
	denied = octstr_imm(tab[i].denied);
	ip = octstr_imm(tab[i].ip);
	socket_enable_ipv6(tab[i].ipv6);
	result = is_allowed_ip(allowed, denied, ip);
	if (!!result != !!tab[i].should_be_allowed) {
	    panic(0, "is_allowed_ip did not work for "
	    	     "ipv6=%d allowed=<%s> denied=<%s> ip=<%s>, "
		     "returned %d should be %d",
		     tab[i].ipv6,
		     octstr_get_cstr(allowed),
		     octstr_get_cstr(denied),
		     octstr_get_cstr(ip),
		     result,
		     tab[i].should_be_allowed);
	}
    }

    gwlib_shutdown();
    return 0;
}
