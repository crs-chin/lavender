/*
 * kconf.c
 * Copyright (C) 2013  Crs Chin <crs.chin@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <zlib.h>

#include "util.h"
#include "kconf.h"
#include "cactus_log.h"

typedef struct _kconf_val kconf_val;

struct _kconf_val{
    char *key;
#define KCONF_VAL_MASK 0xFF
#define KCONF_VAL_LEN 8

#define KCONF_F_DEF 0
#define KCONF_F_OPT (1 << KCONF_VAL_LEN)
    int val;
};

#define __KCONF_DEF(k,v)  {#k, v}
#define KCONF_DEF(k,f) __KCONF_DEF(k,KCONF_F_##f|KCONF_U)

static kconf_val kconf_table[] = {
    KCONF_DEF(NET, DEF),
    KCONF_DEF(UNIX, DEF),
    KCONF_DEF(INET, DEF),
    KCONF_DEF(INET_DIAG, DEF),
    KCONF_DEF(INET_TCP_DIAG, DEF),
    KCONF_DEF(INET_UDP_DIAG, OPT),
    KCONF_DEF(NETFILTER, DEF),
    KCONF_DEF(NETFILTER_NETLINK, DEF),
    KCONF_DEF(NETFILTER_NETLINK_QUEUE, DEF),
    KCONF_DEF(NF_CONNTRACK, DEF),
    KCONF_DEF(NF_CONNTRACK_MARK, DEF),
    KCONF_DEF(NF_CONNTRACK_EVENTS, DEF),
    KCONF_DEF(NF_CT_NETLINK, DEF),
    KCONF_DEF(NETFILTER_XTABLES, DEF),
    KCONF_DEF(NETFILTER_XT_CONNMARK, DEF),
    KCONF_DEF(NETFILTER_XT_TARGET_NFQUEUE, DEF),
    KCONF_DEF(NETFILTER_XT_MATCH_CONNMARK, DEF),
    KCONF_DEF(NETFILTER_XT_MATCH_STATE, DEF),
    KCONF_DEF(NF_CONNTRACK_IPV4, DEF),
};

static void load_config(const char *path)
{
    gzFile f;
    char buf[1024], *k, *v;
    kconf_val *val;
    size_t i;

    LOG_INFO("using kernel config \"%s\"", path);
    if(! (f = gzopen(path, "r")))  {
        LOG_ERROR("failing open kernel config \"%s\"", path);
        return;
    }

    /* if config available, undefined is false */
    for(i = 0, val = kconf_table; i < arraysize(kconf_table); i++, val++)  {
        val->val &= ~KCONF_VAL_MASK;
        val->val |= KCONF_N;
    }

    for(;;)  {
        if(! (k = gzgets(f, buf, sizeof(buf))))
            break;
        while(*k && isspace(*k))
            k++;
        if(! *k || *k == '#')
            continue;
        if(! (v = strchr(k, '=')))
            continue;
        if(v - k <= (int)strlen("CONFIG_"))
            continue;
        k += strlen("CONFIG_");
        *v++ = '\0';
        for(i = 0, val = kconf_table; i < arraysize(kconf_table); i++, val++)  {
            if(! strcmp(val->key, k))  {
                val->val &= ~KCONF_VAL_MASK;
                switch(*v)  {
                case 'y':
                    val->val |= KCONF_Y;
                    break;
                case 'm':
                    val->val |= KCONF_M;
                    break;
                default:
                    break;
                }
            }
        }
    }

    gzclose(f);
}

static int kconf_verify(int flags)
{
    kconf_val *val;
    size_t i;
    int v, ret = 0;

    for(val = kconf_table, i = 0; i < arraysize(kconf_table); val++, i++)  {
        v = val->val & KCONF_VAL_MASK;
        switch(v)  {
        case KCONF_U:
            if((flags & KCONF_F_STRICT)
               && ! (val->val & KCONF_F_OPT))
                ret = -1;
            LOG_WARN("kconf CONFIG_%s undefined", val->key);
            break;
        case KCONF_N:
            if(! (val->val & KCONF_F_OPT))
                ret = -1;
            LOG_WARN("kconf CONFIG_%s disabled", val->key);
            break;
        case KCONF_Y:
        case KCONF_M:
            break;
        default:
            LOG_EMERG("unexpected kconf value:%d", v);
            break;
        }
    }
    LOG_INFO("kconf verify %s!", ret ? "FAIL" : "PASS");
    return ret;
}

int kconf_init_check(int flags)
{
    struct utsname u;
    char buf[PATH_MAX];
    const char *path = "/proc/config.gz";

    if(access(path, R_OK))  {
        path = NULL;
        if(! uname(&u))  {
            snprintf(buf, sizeof(buf), "/lib/modules/%s/build/.config", u.release);
            if(! access(buf, R_OK))
                path = buf;
        }
    }

    if(path)
        load_config(path);
    else
        LOG_WARN("no kernel config info available, using the default");

    return kconf_verify(flags);
}

int kconf_get(const char *conf)
{
    kconf_val *val;
    size_t i;

    for(val = kconf_table, i = 0; i < arraysize(kconf_table); i++, val++)  {
        if(! strcmp(conf, val->key))
            return val->val & KCONF_VAL_MASK;
    }

    return KCONF_U;
}

