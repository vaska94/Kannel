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
 * test_pcre.c - test pcre module
 *
 * Stipe Tolj <stolj@wapme.de>
 */

#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "gwlib/gwlib.h"
#include "gwlib/pcre.h"

#ifdef HAVE_PCRE

int main(int argc, char **argv)
{
    Octstr *re, *os;
    pcre *regexp;
    int ovector[PCRE_OVECCOUNT];
    int rc;

    gwlib_init();

    get_and_set_debugs(argc, argv, NULL);

    if (argc < 3) {
        error(0, "Usage: %s <string> <regex>", argv[0]);
        gwlib_shutdown();
        return 1;
    }

    os = octstr_create(argv[1]);
    re = octstr_create(argv[2]);

    info(0, "step 1: generic functions");

    /* compile */
    if ((regexp = gw_pcre_comp(re, 0)) == NULL)
        panic(0, "pcre compilation failed!");

    /* execute */
    rc = gw_pcre_exec(regexp, os, 0, 0, ovector, PCRE_OVECCOUNT);
    if (rc == PCRE_ERROR_NOMATCH) {
        info(0, "RE: pcre <%s> did not match on string <%s>.",
             octstr_get_cstr(re), octstr_get_cstr(os));
    } else if (rc < 0) {
        error(0, "RE: pcre <%s> execution failed with error %d.",
              octstr_get_cstr(re), rc);
    } else {
        info(0, "RE: pcre <%s> matches.", octstr_get_cstr(re));
    }
    
    info(0, "step 2: wrapper functions");

    debug("pcre",0,"RE: pcre_match <%s> on <%s> did: %s",
          octstr_get_cstr(re), octstr_get_cstr(os),
          gw_pcre_match(re, os) ? "match" : "NOT match");

    debug("pcre",0,"RE: pcre_match_pre on <%s> did: %s",
          octstr_get_cstr(os),
          gw_pcre_match_pre(regexp, os) ? "match" : "NOT match");

    octstr_destroy(re);
    octstr_destroy(os);
    gwlib_shutdown();
    return 0;
}

#else

int main(int argc, char **argv)
{
    printf("PCRE support not compiled in\n");
    return 0;
}

#endif
