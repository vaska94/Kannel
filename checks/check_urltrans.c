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
 * check_urltrans.c - escape-code substitution in urltrans
 *
 * Covers the shell escaping used for `exec' sms-services, where the value
 * has to be escaped for the quoting that already surrounds the escape code
 * in the operator's pattern, and checks that URL substitution is unaffected.
 */

#include "gwlib/gwlib.h"
#include "gw/urltrans.h"
#include "gw/msg.h"
#include "gw/sms.h"

struct cs {
    const char *pattern;
    const char *msgdata;
    const char *expected;
};

/*
 * Command lines. A value must come out as inert data whatever quoting the
 * pattern puts around the escape code: bare, "..." and '...' each need a
 * different escaping, and $(...)/`...` start a fresh command context.
 */
static struct cs shell_cases[] = {
    /* bare: wrap the value in single quotes */
    { "H %S", "kw $(id)",   "H '$(id)'" },
    { "H %S", "kw `id`",    "H '`id`'" },
    { "H %A", "kw ; id ;",  "H 'kw ; id ;'" },
    { "H %S", "kw a'b",     "H 'a'\\''b'" },
    { "H %S", "kw a\"b",    "H 'a\"b'" },
    { "H %S", "kw a\\b",    "H 'a\\b'" },

    /* inside the pattern's double quotes: single quotes would be inert
     * there, so escape what the shell still expands */
    { "H \"%S\"", "kw $(id)", "H \"\\$(id)\"" },
    { "H \"%S\"", "kw `id`",  "H \"\\`id\\`\"" },
    { "H \"%S\"", "kw a\"b",  "H \"a\\\"b\"" },
    { "H \"%S\"", "kw a\\b",  "H \"a\\\\b\"" },
    { "H \"%A\"", "$(id)",    "H \"\\$(id)\"" },

    /* inside the pattern's single quotes: only the quote itself matters */
    { "H '%S'", "kw abc",   "H 'abc'" },
    { "H '%S'", "kw a'b",   "H 'a'\\''b'" },

    /* command substitution is a new command: back to bare quoting */
    { "H $(echo %S)",     "kw abc", "H $(echo 'abc')" },
    { "H \"$(echo %S)\"", "kw abc", "H \"$(echo 'abc')\"" },

    { NULL, NULL, NULL }
};

/*
 * URLs. Unchanged by the shell escaping: %S stays deliberately un-encoded --
 * that is the whole difference between it and %s -- and still maps '*' to '~'.
 */
static struct cs url_cases[] = {
    { "http://x/?t=%A", "hello world&a=1", "http://x/?t=hello+world%26a%3D1" },
    { "http://x/?t=%S", "kw a*b",          "http://x/?t=a~b" },
    { "http://x/?t=%S", "kw $(id)",        "http://x/?t=$(id)" },
    { "http://x/?t=%a", "kw one two",      "http://x/?t=kw+one+two" },
    { NULL, NULL, NULL }
};

static void run(struct cs *cases, int escape_type, const char *what)
{
    Octstr *pattern, *result;
    Msg *msg;
    int i;

    for (i = 0; cases[i].pattern != NULL; ++i) {
        msg = msg_create(sms);
        msg->sms.msgdata  = octstr_create(cases[i].msgdata);
        msg->sms.sender   = octstr_create("+15550001");
        msg->sms.receiver = octstr_create("+15550002");
        msg->sms.coding   = DC_7BIT;

        pattern = octstr_create(cases[i].pattern);
        result = urltrans_fill_escape_codes_ex(pattern, msg, escape_type);

        if (octstr_str_compare(result, cases[i].expected) != 0)
            panic(0, "%s: pattern <%s> with <%s> gave <%s>, expected <%s>",
                  what, cases[i].pattern, cases[i].msgdata,
                  octstr_get_cstr(result), cases[i].expected);

        octstr_destroy(pattern);
        octstr_destroy(result);
        msg_destroy(msg);
    }
}

int main(void)
{
    gwlib_init();
    log_set_output_level(GW_INFO);

    run(shell_cases, URLTRANS_ESCAPE_SHELL, "shell escaping");
    run(url_cases, URLTRANS_ESCAPE_URL, "url escaping");

    gwlib_shutdown();
    return 0;
}
