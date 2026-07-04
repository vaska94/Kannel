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
 * bb_http.c : bearerbox http adminstration commands
 *
 * NOTE: this is a special bearerbox module - it does call
 *   functions from core module! (other modules are fully
 *    encapsulated, and only called outside)
 *
 * Kalle Marjola <rpr@wapit.com> 2000 for project Kannel
 */

#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include "gwlib/gwlib.h"
#include "bearerbox.h"
#include "admin_panel.h"

/* passed from bearerbox core */

extern volatile sig_atomic_t bb_status;

/* our own thingies */

static volatile sig_atomic_t httpadmin_running;

static long	ha_port;
static Octstr *ha_interface;
static Octstr *ha_password;
static Octstr *ha_status_pw;
static Octstr *ha_allow_ip;
static Octstr *ha_deny_ip;


/*---------------------------------------------------------
 * static functions
 */

/*
 * check if the password matches. Return NULL if
 * it does (or is not required)
 */
static Octstr *httpd_check_authorization(List *cgivars, int status)
{
    Octstr *password;
    static double sleep = 0.01;

    password = http_cgi_variable(cgivars, "password");

    if (status) {
	if (ha_status_pw == NULL)
	    return NULL;

	if (password == NULL)
	    goto denied;

	if (octstr_compare(password, ha_password)!=0
	    && octstr_compare(password, ha_status_pw)!=0)
	    goto denied;
    }
    else {
	if (password == NULL || octstr_compare(password, ha_password)!=0)
	    goto denied;
    }
    sleep = 0.0;
    return NULL;	/* allowed */
denied:
    gwthread_sleep(sleep);
    sleep += 1.0;		/* little protection against brute force
				 * password cracking */
    return octstr_create("Denied");
}

/*
 * check if we still have time to do things
 */
static Octstr *httpd_check_status(void)
{
    if (bb_status == BB_SHUTDOWN || bb_status == BB_DEAD)
	return octstr_create("Avalanche has already started, too late to "
	    	    	     "save the sheeps");
    return NULL;
}
    
static Octstr *httpd_status(List *cgivars, int status_type)
{
    Octstr *reply;
    if ((reply = httpd_check_authorization(cgivars, 1))!= NULL) return reply;
    return bb_print_status(status_type);
}

static Octstr *httpd_store_status(List *cgivars, int status_type)
{
    Octstr *reply;
    if ((reply = httpd_check_authorization(cgivars, 1))!= NULL) return reply;
    return store_status(status_type);
}

static Octstr *httpd_loglevel(List *cgivars, int status_type)
{
    Octstr *reply;
    Octstr *level;
    int new_loglevel;
    
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if ((reply = httpd_check_status())!= NULL) return reply;
 
    /* check if new loglevel is given */
    level = http_cgi_variable(cgivars, "level");
    if (level) {
        new_loglevel = atoi(octstr_get_cstr(level));
        log_set_log_level(new_loglevel);
        return octstr_format("log-level set to %d", new_loglevel);
    }
    else {
        return octstr_create("New level not given");
    }
}

static Octstr *httpd_shutdown(List *cgivars, int status_type)
{
    Octstr *reply;
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if (bb_status == BB_SHUTDOWN)
	bb_status = BB_DEAD;
    else {
	bb_shutdown();
        gwthread_wakeup(MAIN_THREAD_ID);
    }
    return octstr_create("Bringing system down");
}

static Octstr *httpd_isolate(List *cgivars, int status_type)
{
    Octstr *reply;
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if ((reply = httpd_check_status())!= NULL) return reply;

    if (bb_isolate() == -1)
	return octstr_create("Already isolated");
    else
	return octstr_create(GW_NAME " isolated from message providers");
}

static Octstr *httpd_suspend(List *cgivars, int status_type)
{
    Octstr *reply;
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if ((reply = httpd_check_status())!= NULL) return reply;

    if (bb_suspend() == -1)
	return octstr_create("Already suspended");
    else
	return octstr_create(GW_NAME " suspended");
}

static Octstr *httpd_resume(List *cgivars, int status_type)
{
    Octstr *reply;
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if ((reply = httpd_check_status())!= NULL) return reply;
 
    if (bb_resume() == -1)
	return octstr_create("Already running");
    else
	return octstr_create("Running resumed");
}

static Octstr *httpd_restart(List *cgivars, int status_type)
{
    Octstr *reply;
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if ((reply = httpd_check_status())!= NULL) return reply;
 
    if (bb_status == BB_SHUTDOWN) {
        bb_status = BB_DEAD;
        gwthread_wakeup_all();
        return octstr_create("Trying harder to restart");
    }
    bb_restart();
    return octstr_create("Restarting.....");
}

static Octstr *httpd_graceful_restart(List *cgivars, int status_type)
{
    Octstr *reply;
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if ((reply = httpd_check_status())!= NULL) return reply;

    if (bb_status == BB_SHUTDOWN) {
        bb_status = BB_DEAD;
        bb_restart();
        return octstr_create("Already in shutdown phase, restarting hard...");
    }
    if (bb_graceful_restart() == -1)
        return octstr_create("Unable to restart gracefully! Please check log file.");
    else
        return octstr_create("Restarting gracefully.....");
}

static Octstr *httpd_flush_dlr(List *cgivars, int status_type)
{
    Octstr *reply;
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if ((reply = httpd_check_status())!= NULL) return reply;

    if (bb_flush_dlr() == -1)
	return octstr_create("Suspend " GW_NAME " before trying to flush DLR queue");
    else
	return octstr_create("DLR queue flushed");
}

static Octstr *httpd_stop_smsc(List *cgivars, int status_type)
{
    Octstr *reply;
    Octstr *smsc;
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if ((reply = httpd_check_status())!= NULL) return reply;

    /* check if the smsc id is given */
    smsc = http_cgi_variable(cgivars, "smsc");
    if (smsc) {
        if (bb_stop_smsc(smsc) == -1)
            return octstr_format("Could not shut down smsc-id `%s'", octstr_get_cstr(smsc));
        else
            return octstr_format("SMSC `%s' shut down", octstr_get_cstr(smsc));
    } else
        return octstr_create("SMSC id not given");
}

static Octstr *httpd_remove_smsc(List *cgivars, int status_type)
{
    Octstr *reply;
    Octstr *smsc;
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if ((reply = httpd_check_status())!= NULL) return reply;

    /* check if the smsc id is given */
    smsc = http_cgi_variable(cgivars, "smsc");
    if (smsc) {
        if (bb_remove_smsc(smsc) == -1)
            return octstr_format("Could not remove smsc-id `%s'", octstr_get_cstr(smsc));
        else
            return octstr_format("SMSC `%s' removed", octstr_get_cstr(smsc));
    } else
        return octstr_create("SMSC id not given");
}

static Octstr *httpd_add_smsc(List *cgivars, int status_type)
{
    Octstr *reply;
    Octstr *smsc;
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if ((reply = httpd_check_status())!= NULL) return reply;

    /* check if the smsc id is given */
    smsc = http_cgi_variable(cgivars, "smsc");
    if (smsc) {
        if (bb_add_smsc(smsc) == -1)
            return octstr_format("Could not add smsc-id `%s'", octstr_get_cstr(smsc));
        else
            return octstr_format("SMSC `%s' added", octstr_get_cstr(smsc));
    } else
        return octstr_create("SMSC id not given");
}

static Octstr *httpd_restart_smsc(List *cgivars, int status_type)
{
    Octstr *reply;
    Octstr *smsc;
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if ((reply = httpd_check_status())!= NULL) return reply;

    /* check if the smsc id is given */
    smsc = http_cgi_variable(cgivars, "smsc");
    if (smsc) {
        if (bb_restart_smsc(smsc) == -1)
            return octstr_format("Could not re-start smsc-id `%s'", octstr_get_cstr(smsc));
        else
            return octstr_format("SMSC `%s' re-started", octstr_get_cstr(smsc));
    } else
        return octstr_create("SMSC id not given");
}

static Octstr *httpd_reload_lists(List *cgivars, int status_type)
{
    Octstr *reply;
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if ((reply = httpd_check_status())!= NULL) return reply;
 
    if (bb_reload_lists() == -1)
        return octstr_create("Could not re-load lists");
    else
        return octstr_create("Black/white lists re-loaded");
}

static Octstr *httpd_remove_message(List *cgivars, int status_type)
{
    Octstr *reply;
    Octstr *message_id;
    if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
    if ((reply = httpd_check_status())!= NULL) return reply;

    /* check if the smsc id is given */
    message_id = http_cgi_variable(cgivars, "id");
    if (message_id) {
        if (octstr_len(message_id) != UUID_STR_LEN)
            return octstr_format("Message id should be %d characters long", UUID_STR_LEN);
        if (bb_remove_message(message_id) == -1)
            return octstr_format("Could not remove message id `%s'", octstr_get_cstr(message_id));
        else
            return octstr_format("Message id `%s' removed", octstr_get_cstr(message_id));
    } else
        return octstr_create("Message id not given");
}

/*
 * SMSC directives that may be set through the admin panel. 'smsc' (type) and
 * 'smsc-id' are mandatory and handled explicitly; everything else is optional
 * and only written when supplied. This is a strict allow-list: any CGI
 * variable not named here is ignored, so the endpoint cannot be used to inject
 * arbitrary core/group directives.
 */
static const char *smsc_cfg_allowed[] = {
    "host", "port", "receive-port", "our-port",
    "smsc-username", "smsc-password", "system-type", "system-id",
    "interface-version", "address-range", "msg-id-type",
    "source-addr-ton", "source-addr-npi", "dest-addr-ton", "dest-addr-npi",
    "transceiver-mode", "connect-allow-ip",
    "allowed-smsc-id", "denied-smsc-id", "preferred-smsc-id",
    "reconnect-delay", "throughput", "window", "instances", "log-level",
    NULL
};

/* smsc-id is used verbatim as a filename, so keep it to a safe charset */
static int smsc_cfg_valid_id(Octstr *id)
{
    long i, len = octstr_len(id);

    if (len == 0 || len > 64)
        return 0;
    for (i = 0; i < len; i++) {
        int c = octstr_get_char(id, i);
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

static int smsc_cfg_valid_type(Octstr *type)
{
    long i, len = octstr_len(type);

    if (len == 0 || len > 32)
        return 0;
    for (i = 0; i < len; i++) {
        int c = octstr_get_char(type, i);
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

/* reject values that would break the line-based config format */
static int smsc_cfg_has_ctrl(Octstr *v)
{
    long i, len = octstr_len(v);

    for (i = 0; i < len; i++) {
        int c = octstr_get_char(v, i);
        if (c == '\r' || c == '\n' || c == '\0')
            return 1;
    }
    return 0;
}

/*
 * Quote a value for the config file. cfg's parse_value() strips one layer of
 * surrounding double quotes and un-escapes \\ and \", so escaping backslash
 * and double-quote here round-trips any value safely (spaces included).
 */
static Octstr *smsc_cfg_quote(Octstr *value)
{
    Octstr *out = octstr_create("\"");
    Octstr *tmp = octstr_duplicate(value);

    octstr_replace(tmp, octstr_imm("\\"), octstr_imm("\\\\"));
    octstr_replace(tmp, octstr_imm("\""), octstr_imm("\\\""));
    octstr_append(out, tmp);
    octstr_append_cstr(out, "\"");
    octstr_destroy(tmp);
    return out;
}

static Octstr *httpd_save_smsc_config(List *cgivars, int status_type)
{
    Octstr *reply, *id, *type, *block, *val, *q;
    int i;

    if ((reply = httpd_check_authorization(cgivars, 0)) != NULL) return reply;
    if ((reply = httpd_check_status()) != NULL) return reply;

    if (bb_smsc_config_dir() == NULL)
        return octstr_create("Runtime SMSC configuration is disabled "
                             "(set 'smsc-config-dir' in the core group)");

    id = http_cgi_variable(cgivars, "smsc-id");
    type = http_cgi_variable(cgivars, "smsc");
    if (id == NULL || octstr_len(id) == 0)
        return octstr_create("smsc-id is required");
    if (!smsc_cfg_valid_id(id))
        return octstr_create("Invalid smsc-id (allowed: letters, digits, '.', '_', '-'; max 64)");
    if (type == NULL || octstr_len(type) == 0)
        return octstr_create("smsc (type) is required");
    if (!smsc_cfg_valid_type(type))
        return octstr_create("Invalid smsc type (allowed: lowercase letters, digits, '_', '-')");

    /*
     * A network SMSC without a host silently fails to start; because a save
     * triggers a graceful restart, that would drop the previously-working
     * connection and leave only the broken file on disk. Reject it so an
     * incomplete edit can't destroy a working SMSC.
     */
    val = http_cgi_variable(cgivars, "host");
    if ((val == NULL || octstr_len(val) == 0) &&
        octstr_str_compare(type, "fake") != 0 &&
        octstr_str_compare(type, "loopback") != 0)
        return octstr_format("host is required for smsc type `%S'", type);

    block = octstr_create("# SMSC connection managed by the Kamex admin panel\n");
    octstr_append_cstr(block, "group = smsc\n");
    q = smsc_cfg_quote(type);
    octstr_format_append(block, "smsc = %S\n", q);
    octstr_destroy(q);
    q = smsc_cfg_quote(id);
    octstr_format_append(block, "smsc-id = %S\n", q);
    octstr_destroy(q);

    for (i = 0; smsc_cfg_allowed[i] != NULL; i++) {
        val = http_cgi_variable(cgivars, smsc_cfg_allowed[i]);
        if (val == NULL || octstr_len(val) == 0)
            continue;
        if (smsc_cfg_has_ctrl(val)) {
            octstr_destroy(block);
            return octstr_format("Invalid value for `%s' (control characters not allowed)",
                                 smsc_cfg_allowed[i]);
        }
        q = smsc_cfg_quote(val);
        octstr_format_append(block, "%s = %S\n", smsc_cfg_allowed[i], q);
        octstr_destroy(q);
    }

    switch (bb_save_smsc_config(id, block)) {
    case -2:
        octstr_destroy(block);
        return octstr_format("SMSC `%S' did not start and was rolled back. "
                             "Check required fields (SMPP needs host, port, "
                             "username, password and system-type).", id);
    case -1:
        octstr_destroy(block);
        return octstr_format("Failed to save SMSC `%S' (check the log)", id);
    default:
        octstr_destroy(block);
        return octstr_format("SMSC `%S' saved and activated", id);
    }
}

/* append s to out, escaped as a JSON string body (no surrounding quotes) */
static void smsc_cfg_json_append(Octstr *out, Octstr *s)
{
    long i, len = octstr_len(s);

    for (i = 0; i < len; i++) {
        int c = octstr_get_char(s, i);
        switch (c) {
            case '"':  octstr_append_cstr(out, "\\\""); break;
            case '\\': octstr_append_cstr(out, "\\\\"); break;
            case '\n': octstr_append_cstr(out, "\\n"); break;
            case '\r': octstr_append_cstr(out, "\\r"); break;
            case '\t': octstr_append_cstr(out, "\\t"); break;
            default:   octstr_append_char(out, c); break;
        }
    }
}

/*
 * Return the persisted directives of an SMSC as a JSON object so the admin
 * panel can populate the edit form. Requires the admin password (the reply
 * includes the SMSC password). Request with a .json suffix for a JSON reply.
 */
static Octstr *httpd_get_smsc_config(List *cgivars, int status_type)
{
    Octstr *reply, *id, *raw, *json, *line;
    List *lines;
    int first = 1;

    if ((reply = httpd_check_authorization(cgivars, 0)) != NULL) return reply;

    if (bb_smsc_config_dir() == NULL)
        return octstr_create("Runtime SMSC configuration is disabled");

    id = http_cgi_variable(cgivars, "smsc");
    if (id == NULL)
        id = http_cgi_variable(cgivars, "smsc-id");
    if (id == NULL || octstr_len(id) == 0)
        return octstr_create("SMSC id not given");
    if (!smsc_cfg_valid_id(id))
        return octstr_create("Invalid smsc-id");

    raw = bb_read_smsc_config(id);
    if (raw == NULL)
        return octstr_create("{}");   /* unknown id -> empty object */

    json = octstr_create("{");
    lines = octstr_split(raw, octstr_imm("\n"));
    while ((line = gwlist_extract_first(lines)) != NULL) {
        long eq;
        Octstr *key, *val;

        octstr_strip_blanks(line);
        if (octstr_len(line) == 0 || octstr_get_char(line, 0) == '#') {
            octstr_destroy(line);
            continue;
        }
        eq = octstr_search_char(line, '=', 0);
        if (eq < 0) { octstr_destroy(line); continue; }
        key = octstr_copy(line, 0, eq);
        val = octstr_copy(line, eq + 1, octstr_len(line) - eq - 1);
        octstr_strip_blanks(key);
        octstr_strip_blanks(val);
        if (octstr_str_compare(key, "group") == 0) {
            octstr_destroy(key); octstr_destroy(val); octstr_destroy(line);
            continue;
        }
        /* reverse of smsc_cfg_quote(): drop surrounding quotes, unescape */
        if (octstr_len(val) >= 2 && octstr_get_char(val, 0) == '"' &&
            octstr_get_char(val, octstr_len(val) - 1) == '"') {
            octstr_delete(val, octstr_len(val) - 1, 1);
            octstr_delete(val, 0, 1);
            octstr_replace(val, octstr_imm("\\\""), octstr_imm("\""));
            octstr_replace(val, octstr_imm("\\\\"), octstr_imm("\\"));
        }
        if (!first) octstr_append_char(json, ',');
        first = 0;
        octstr_append_char(json, '"');
        smsc_cfg_json_append(json, key);
        octstr_append_cstr(json, "\":\"");
        smsc_cfg_json_append(json, val);
        octstr_append_char(json, '"');
        octstr_destroy(key); octstr_destroy(val); octstr_destroy(line);
    }
    gwlist_destroy(lines, octstr_destroy_item);
    octstr_append_char(json, '}');
    octstr_destroy(raw);
    return json;
}

static Octstr *httpd_delete_smsc_config(List *cgivars, int status_type)
{
    Octstr *reply, *id;

    if ((reply = httpd_check_authorization(cgivars, 0)) != NULL) return reply;
    if ((reply = httpd_check_status()) != NULL) return reply;

    if (bb_smsc_config_dir() == NULL)
        return octstr_create("Runtime SMSC configuration is disabled "
                             "(set 'smsc-config-dir' in the core group)");

    id = http_cgi_variable(cgivars, "smsc");
    if (id == NULL)
        id = http_cgi_variable(cgivars, "smsc-id");
    if (id == NULL || octstr_len(id) == 0)
        return octstr_create("SMSC id not given");
    if (!smsc_cfg_valid_id(id))
        return octstr_create("Invalid smsc-id");

    if (bb_delete_smsc_config(id) == -1)
        return octstr_format("Failed to delete SMSC `%S' (check the log)", id);
    return octstr_format("SMSC `%S' deleted", id);
}

/* Known httpd commands and their functions */
static struct httpd_command {
    const char *command;
    Octstr * (*function)(List *cgivars, int status_type);
} httpd_commands[] = {
    { "status", httpd_status },
    { "store-status", httpd_store_status },
    { "log-level", httpd_loglevel },
    { "shutdown", httpd_shutdown },
    { "suspend", httpd_suspend },
    { "isolate", httpd_isolate },
    { "resume", httpd_resume },
    { "restart", httpd_restart },
    { "graceful-restart", httpd_graceful_restart },
    { "flush-dlr", httpd_flush_dlr },
    { "stop-smsc", httpd_stop_smsc },
    { "start-smsc", httpd_restart_smsc },
    { "add-smsc", httpd_add_smsc },
    { "remove-smsc", httpd_remove_smsc },
    { "save-smsc-config", httpd_save_smsc_config },
    { "get-smsc-config", httpd_get_smsc_config },
    { "delete-smsc-config", httpd_delete_smsc_config },
    { "reload-lists", httpd_reload_lists },
    { "remove-message", httpd_remove_message },
    { NULL , NULL } /* terminate list */
};

static void httpd_serve_admin(HTTPClient *client, List *headers)
{
    List *response_headers;
    Octstr *html;

    http_destroy_headers(headers);
    response_headers = gwlist_create();

    html = octstr_create(admin_panel_html);
    http_header_add(response_headers, "Content-Type", "text/html; charset=utf-8");
    http_send_reply(client, HTTP_OK, response_headers, html);
    octstr_destroy(html);

    http_destroy_headers(response_headers);
}

static void httpd_serve_health(HTTPClient *client, List *headers)
{
    Octstr *reply;
    List *response_headers;
    int is_healthy;
    int http_status;

    reply = bb_health_status(&is_healthy);
    http_status = is_healthy ? HTTP_OK : HTTP_SERVICE_UNAVAILABLE;

    http_destroy_headers(headers);
    response_headers = gwlist_create();
    http_header_add(response_headers, "Content-Type", "application/json");

    http_send_reply(client, http_status, response_headers, reply);

    octstr_destroy(reply);
    http_destroy_headers(response_headers);
}

static void httpd_serve_metrics(HTTPClient *client, List *headers)
{
    Octstr *reply;
    List *response_headers;

    reply = bb_prometheus_metrics();

    http_destroy_headers(headers);
    response_headers = gwlist_create();
    http_header_add(response_headers, "Content-Type",
                    "text/plain; version=0.0.4; charset=utf-8");

    http_send_reply(client, HTTP_OK, response_headers, reply);

    octstr_destroy(reply);
    http_destroy_headers(response_headers);
}


static void httpd_serve(HTTPClient *client, Octstr *ourl, List *headers,
    	    	    	Octstr *body, List *cgivars)
{
    Octstr *reply, *final_reply, *url;
    char *content_type;
    char *header, *footer;
    int status_type;
    int i;
    long pos;

    reply = final_reply = NULL; /* for compiler please */
    url = octstr_duplicate(ourl);

    /* Set default reply format according to client
     * Accept: header */
    if (http_type_accepted(headers, "text/html")) {
        status_type = BBSTATUS_HTML;
        content_type = "text/html";
    }
    else if (http_type_accepted(headers, "text/xml")) {
        status_type = BBSTATUS_XML;
        content_type = "text/xml";
    }
    else if (http_type_accepted(headers, "application/xml")) {
        status_type = BBSTATUS_XML;
        content_type = "application/xml";
    }
    else {
        status_type = BBSTATUS_TEXT;
        content_type = "text/plain";
    }

    /* kill '/cgi-bin' prefix */
    pos = octstr_search(url, octstr_imm("/cgi-bin/"), 0);
    if (pos != -1)
        octstr_delete(url, pos, 9);
    else if (octstr_get_char(url, 0) == '/')
        octstr_delete(url, 0, 1);

    /* look for type and kill it */
    pos = octstr_search_char(url, '.', 0);
    if (pos != -1) {
        Octstr *tmp = octstr_copy(url, pos+1, octstr_len(url) - pos - 1);
        octstr_delete(url, pos, octstr_len(url) - pos);

        if (octstr_str_compare(tmp, "txt") == 0) {
            status_type = BBSTATUS_TEXT;
            content_type = "text/plain";
        }
        else if (octstr_str_compare(tmp, "html") == 0) {
            status_type = BBSTATUS_HTML;
            content_type = "text/html";
        }
        else if (octstr_str_compare(tmp, "xml") == 0) {
            status_type = BBSTATUS_XML;
            content_type = "application/xml";
        }
        else if (octstr_str_compare(tmp, "json") == 0) {
            status_type = BBSTATUS_JSON;
            content_type = "application/json";
        }

        octstr_destroy(tmp);
    }

    /* Handle /health endpoint specially - no auth required, returns proper HTTP status */
    if (octstr_str_compare(url, "health") == 0) {
        octstr_destroy(url);
        octstr_destroy(ourl);
        octstr_destroy(body);
        http_destroy_cgiargs(cgivars);
        httpd_serve_health(client, headers);
        return;
    }

    /* Handle /metrics endpoint - Prometheus metrics, no auth required */
    if (octstr_str_compare(url, "metrics") == 0) {
        octstr_destroy(url);
        octstr_destroy(ourl);
        octstr_destroy(body);
        http_destroy_cgiargs(cgivars);
        httpd_serve_metrics(client, headers);
        return;
    }

    /* Handle / and /admin endpoints - serves admin panel HTML */
    if (octstr_len(url) == 0 || octstr_str_compare(url, "admin") == 0) {
        octstr_destroy(url);
        octstr_destroy(ourl);
        octstr_destroy(body);
        http_destroy_cgiargs(cgivars);
        httpd_serve_admin(client, headers);
        return;
    }

    for (i=0; httpd_commands[i].command != NULL; i++) {
        if (octstr_str_compare(url, httpd_commands[i].command) == 0) {
            reply = httpd_commands[i].function(cgivars, status_type);
            break;
        }
    }

    /* check if command found */
    if (httpd_commands[i].command == NULL) {
        char *lb = bb_status_linebreak(status_type);
	reply = octstr_format("Unknown command `%S'.%sPossible commands are:%s",
            ourl, lb, lb);
        for (i=0; httpd_commands[i].command != NULL; i++)
            octstr_format_append(reply, "%s%s", httpd_commands[i].command, lb);
    }

    gw_assert(reply != NULL);

    if (status_type == BBSTATUS_HTML) {
	header = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n"
 	    "<html>\n<title>" GW_NAME "</title>\n<body>\n<p>";
	footer = "</p>\n</body></html>\n";
	content_type = "text/html";
    } else if (status_type == BBSTATUS_XML) {
	header = "<?xml version=\"1.0\"?>\n"
            "<gateway>\n";
        footer = "</gateway>\n";
    } else if (status_type == BBSTATUS_JSON) {
	header = "";
	footer = "";
	content_type = "application/json";
    } else {
	header = "";
	footer = "";
	content_type = "text/plain";
    }
    final_reply = octstr_create(header);
    octstr_append(final_reply, reply);
    octstr_append_cstr(final_reply, footer);
    
    /* debug("bb.http", 0, "Result: '%s'", octstr_get_cstr(final_reply));
     */
    http_destroy_headers(headers);
    headers = gwlist_create();
    http_header_add(headers, "Content-Type", content_type);

    http_send_reply(client, HTTP_OK, headers, final_reply);

    octstr_destroy(url);
    octstr_destroy(ourl);
    octstr_destroy(body);
    octstr_destroy(reply);
    octstr_destroy(final_reply);
    http_destroy_headers(headers);
    http_destroy_cgiargs(cgivars);
}

static void httpadmin_run(void *arg)
{
    HTTPClient *client;
    Octstr *ip, *url, *body;
    List *headers, *cgivars;

    while(bb_status != BB_DEAD) {
	if (bb_status == BB_SHUTDOWN)
	    bb_shutdown();
    	client = http_accept_request(ha_port, &ip, &url, &headers, &body, 
	    	    	    	     &cgivars);
	if (client == NULL)
	    break;
	if (is_allowed_ip(ha_allow_ip, ha_deny_ip, ip) == 0) {
	    info(0, "HTTP admin tried from denied host <%s>, disconnected",
		 octstr_get_cstr(ip));
	    http_close_client(client);
	    continue;
	}
        httpd_serve(client, url, headers, body, cgivars);
	octstr_destroy(ip);
    }

    httpadmin_running = 0;
}


/*-------------------------------------------------------------
 * public functions
 *
 */

int httpadmin_start(Cfg *cfg)
{
    CfgGroup *grp;
    int ssl = 0; 
#ifdef HAVE_LIBSSL
    Octstr *ssl_server_cert_file;
    Octstr *ssl_server_key_file;
#endif /* HAVE_LIBSSL */
    
    if (httpadmin_running) return -1;


    grp = cfg_get_single_group(cfg, octstr_imm("core"));
    if (cfg_get_integer(&ha_port, grp, octstr_imm("admin-port")) == -1)
	panic(0, "Missing admin-port variable, cannot start HTTP admin");

    ha_interface = cfg_get(grp, octstr_imm("admin-interface"));
    ha_password = cfg_get(grp, octstr_imm("admin-password"));
    if (ha_password == NULL)
	panic(0, "You MUST set HTTP admin-password");
    
    ha_status_pw = cfg_get(grp, octstr_imm("status-password"));

    ha_allow_ip = cfg_get(grp, octstr_imm("admin-allow-ip"));
    ha_deny_ip = cfg_get(grp, octstr_imm("admin-deny-ip"));

#ifdef HAVE_LIBSSL
    cfg_get_bool(&ssl, grp, octstr_imm("admin-port-ssl"));
    
    /*
     * check if SSL is desired for HTTP servers and then
     * load SSL client and SSL server public certificates 
     * and private keys
     */    
    ssl_server_cert_file = cfg_get(grp, octstr_imm("ssl-server-cert-file"));
    ssl_server_key_file = cfg_get(grp, octstr_imm("ssl-server-key-file"));
    if (ssl_server_cert_file != NULL && ssl_server_key_file != NULL) {
        /* we are fine here, the following call is now in conn_config_ssl(),
         * so there is no reason to do this twice.

        use_global_server_certkey_file(ssl_server_cert_file, 
            ssl_server_key_file);
        */
    } else if (ssl) {
	   panic(0, "You MUST specify cert and key files within core group for SSL-enabled HTTP servers!");
    }

    octstr_destroy(ssl_server_cert_file);
    octstr_destroy(ssl_server_key_file);
#endif /* HAVE_LIBSSL */

    http_open_port_if(ha_port, ssl, ha_interface);

    info(0, "Admin panel available at / and /admin");

    if (gwthread_create(httpadmin_run, NULL) == -1)
	panic(0, "Failed to start a new thread for HTTP admin");

    httpadmin_running = 1;
    return 0;
}


void httpadmin_stop(void)
{
    http_close_all_ports();
    gwthread_join_every(httpadmin_run);
    octstr_destroy(ha_interface);
    octstr_destroy(ha_password);
    octstr_destroy(ha_status_pw);
    octstr_destroy(ha_allow_ip);
    octstr_destroy(ha_deny_ip);
    ha_password = NULL;
    ha_status_pw = NULL;
    ha_allow_ip = NULL;
    ha_deny_ip = NULL;
}
