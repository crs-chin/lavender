/*
 * Copyright (C) 2012  Crs Chin <crs.chin@gmail.com>
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

#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "util.h"
#include "msg_base.h"
#include "msg.h"
#include "gardenia.h"
#include "cactus_log.h"
#include "fd_lookup.h"
#include "ginkgo.h"
#include "rtnl.h"
#include "uevent.h"
#include "nfct.h"
#include "core.h"

#ifndef CONFIG_LOG_FILE_PATH
#define CONFIG_LOG_FILE_PATH "/var/log/" PACKAGE_NAME "/"
#endif

#ifndef CONFIG_LOG_FILE_PREFIX
#define CONFIG_LOG_FILE_PREFIX PACKAGE_NAME
#endif

#define TIME_FORMAT "[%02d/%02d %02d:%02d:%02d]"
#define TIME_ARG(tm) tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec

static int log_init = 0;
static pthread_mutex_t log_lock[NUM_LOG] = {
    [0 ... NUM_LOG - 1] = PTHREAD_MUTEX_INITIALIZER,
};
static gardenia *log_pool[NUM_LOG] = {
    [0 ... NUM_LOG - 1] = NULL,
};
int log_ctl[NUM_LOG];
int log_mask[NUM_LVL];

static const char *level_tbl[] = {
    "DEBUG", "INFO", "WARN", "EMERG", "ERROR", "FATAL",
};

static const char *prefix_tbl[] = {
    CONFIG_LOG_FILE_PREFIX "_main",
    CONFIG_LOG_FILE_PREFIX "_rtnl",
    CONFIG_LOG_FILE_PREFIX "_uevent",
    CONFIG_LOG_FILE_PREFIX "_conntrack",
};


int cactus_log_init(void)
{
    int i;

    if(! log_init)  {
        /* object log disabled by default */
        for(i = 0; i < NUM_LOG; i++)
            log_ctl[i] = 0;
        log_ctl[LOG_MAIN] = 1;

        for(i = 0; i < NUM_LVL; i++)  {
            /* disable debug level log by default */
            if(i == LOG_DEBUG)
                log_mask[i] = 0;
            else
                log_mask[i] = 1;
        }

        for(i = 0; i < NUM_LOG; i++)  {
            if(! (log_pool[i] = gardenia_create(CONFIG_LOG_FILE_PATH,
                                                prefix_tbl[i],
                                                MIN_STORAGE_SIZE,
                                                MIN_ROTATE_SIZE)))
                return -1;
        }
        log_init = 1;
    }
    return 0;
}

void cactus_log_fini(void)
{
    int i;

    if(log_init)  {
        for(i = 0; i < NUM_LOG; i++)  {
            if(log_pool[i])  {
                /* flush logs before exit */
                gardenia_destroy(log_pool[i]);
                log_pool[i] = NULL;
            }
        }
        log_init = 0;
    }
}

static inline int __log_main(int lvl, const char *str)
{
    time_t t = time(NULL);
    struct tm tm;

    localtime_r(&t, &tm);
    return gardenia_print(log_pool[LOG_MAIN], TIME_FORMAT "[%s]%s\n", TIME_ARG(tm), level_tbl[lvl], str);
}

static int __log_rtnl_ts(void)
{
    char _ts[NLMSG_SPACE(4 * 2)];
    struct nlmsghdr *ts = (struct nlmsghdr *)&_ts;
    struct timeval tv = {0, 0};
    __u32 *d = NLMSG_DATA(ts);

    /* rtmon util compliant, so that log file can be parsed using
       command "ip moniter file <LOG_FILE>"  */
    memset(&_ts, 0, sizeof(_ts));
    ts->nlmsg_type = 15;
    ts->nlmsg_len = NLMSG_LENGTH(4 * 2);
    gettimeofday(&tv, NULL);
    d[0] = tv.tv_sec;
    d[1] = tv.tv_usec;
    return gardenia_write(log_pool[LOG_RTNL], &_ts, sizeof(_ts));
}

static inline int __log_rtnl_msg(rtnl_msg *msg)
{
    ginkgo_msg *g = RTNL_GINKGO_MSG(msg);

    assert(g->len > sizeof(ginkgo_msg));
    return gardenia_write(log_pool[LOG_RTNL], g->payload, g->len - sizeof(ginkgo_msg));
}

static inline int __log_rtnl(rtnl_msg *msg)
{
    int len, tmp;

    len = __log_rtnl_ts();
    if(len > 0)  {
        tmp = __log_rtnl_msg(msg);
        if(tmp > 0)
            return len + tmp;
    }
    return -1;
}

static int __log_uevent(uevent_msg *msg)
{
    time_t t = time(NULL);
    struct tm tm;
    gardenia *g = log_pool[LOG_UEVENT];
    char *iter;
    int res, tmp;

    assert(msg);
    localtime_r(&t, &tm);
    res = gardenia_print(g, TIME_FORMAT "==============================\n",
                         TIME_ARG(tm));
    if(res > 0)  {
        tmp = gardenia_print(g, "PATH:%s\n", msg->path ? : "<NULL>");
        if(tmp > 0)  {
            res += tmp;
            uevent_msg_for_each_env(iter, msg)  {
                tmp = gardenia_print(g, "%s\n", iter ? : "<NULL ENV ITEM>");
                if(tmp > 0)
                    res += tmp;
            }list_end;
        }
    }
    return res;
}

static int __log_fos(list *fos)
{
    fd_owner *fo;
    int res = 0, tmp;

    if(! list_empty(fos))  {
        list_for_each_entry(fo, fos, list)  {
            tmp = gardenia_print(log_pool[LOG_CONNTRACK], "EXEC:%s\n  UID:%-5d  GID:%-5d  PID:%-5d  PPID:%-5d\n",
                                 fo->exe, fo->euid, fo->egid, fo->pid, fo->ppid);
            if(tmp > 0)
                res += tmp;
        }
    }
    return res;
}

static int __do_log_conntrack(nfct_msg *msg, time_t *t)
{
    conn_tuple src, dst;
    conn_entry *ent = (conn_entry *)msg->entry;
    conn_counter counter;
    conn_tcpinfo tcpinfo;
    __u32 mark = nfct_conn_mark(ent);
    __u32 use = nfct_conn_use(ent);
    int counter_avail;
    char protonum[20];
    const char *prot = "unknown";
    const char *type = "";
    const char *state = "";
    const char *orig_state = "";
    const char *rep_state = "";
    struct tm tm;
    static const char *tcp_state_tbl[] = {
        "[NONE] ",
        "[SYN SENT] ",
        "[SYN RECV] ",
        "[ESTABLISHED] ",
        "[FIN WAIT] ",
        "[CLOSE WAIT] ",
        "[LAST ACK] ",
        "[TIME WAIT] ",
        "[CLOSED] ",
        "[LISTEN] ",/* obsolete */
    };

    if(nfct_conn_get_src_tuple(ent, &src))  {
        LOG_WARN("fail to get source tuple");
        return -1;
    }

    if(nfct_conn_get_dst_tuple(ent, &dst))  {
        LOG_WARN("fail to get dst tuple");
        return -1;
    }

    counter_avail = ! nfct_conn_get_counter(ent, &counter);
    localtime_r(t, &tm);

    switch(msg->type)  {
    case IPCTNL_MSG_CT_NEW:
        type = "[NEW] ";
        break;
    case IPCTNL_MSG_CT_DELETE:
        type = "[DEL] ";
        break;
    default:
        type = "[UNK] ";
        break;
    }

    switch(src.src.l3num)  {
    case AF_INET:  {
        const unsigned char *ip_src = (const unsigned char *)&src.src.u3.ip;
        const unsigned char *ip_dst = (const unsigned char *)&src.dst.u3.ip;
        const unsigned char *rep_src = (const unsigned char *)&dst.src.u3.ip;
        const unsigned char *rep_dst = (const unsigned char *)&dst.dst.u3.ip;

        switch(src.dst.protonum)  {
        case IPPROTO_TCP:
            prot = "TCP";
            if(! nfct_conn_get_tcpinfo(ent, &tcpinfo))  {
                if(tcpinfo.state >= TCP_CONNTRACK_MAX)
                    state = "[INVALID] ";
                else
                    state = tcp_state_tbl[tcpinfo.state];
            }
            break;
        case IPPROTO_UDP:
            prot = "UDP";
            if(! (ent->status & IPS_SEEN_REPLY))
                orig_state = "[UNREPLIED] ";
            if(ent->status & IPS_ASSURED)
                rep_state = "[ASSURED] ";
            break;
        case IPPROTO_UDPLITE:
            prot = "UDPlite";
            if(! (ent->status & IPS_SEEN_REPLY))
                orig_state = "[UNREPLIED] ";
            if(ent->status & IPS_ASSURED)
                rep_state = "[ASSURED] ";
            break;
        case IPPROTO_ICMP:
            prot = "ICMP";
            if(! (ent->status & IPS_SEEN_REPLY))
                orig_state = "[UNREPLIED] ";
            if(ent->status & IPS_ASSURED)
                rep_state = "[ASSURED] ";
            break;
        default:
            sprintf(protonum, "[%u]", src.src.l3num);
            prot = protonum;
            break;
        }
        if(counter_avail)  {
            return gardenia_print(log_pool[LOG_CONNTRACK], TIME_FORMAT "IPv4 %s %s%ssrc=%u.%u.%u.%u dst=%u.%u.%u.%u "
                                  "sport=%u dport=%u pkts=%llu bytes=%llu %ssrc=%u.%u.%u.%u dst=%u.%u.%u.%u "
                                  "sport=%u dport=%u pkts=%llu bytes=%llu, %smark=%u use=%u\n",
                                  TIME_ARG(tm),
                                  prot, type, state,
                                  ip_src[0], ip_src[1], ip_src[2], ip_src[3],
                                  ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3],
                                  ntohs(src.src.u.tcp.port), ntohs(src.dst.u.tcp.port),
                                  counter.orig_pkts, counter.orig_bytes,
                                  orig_state,
                                  rep_src[0], rep_src[1], rep_src[2], rep_src[3], 
                                  rep_dst[0], rep_dst[1], rep_dst[2], rep_dst[3], 
                                  ntohs(dst.src.u.tcp.port), ntohs(dst.dst.u.tcp.port),
                                  counter.rep_pkts, counter.rep_bytes,
                                  rep_state,
                                  mark, use);
        }else  {
            return gardenia_print(log_pool[LOG_CONNTRACK], TIME_FORMAT "IPv4 %s %s%ssrc=%u.%u.%u.%u dst=%u.%u.%u.%u "
                                  "sport=%u dport=%u %ssrc=%u.%u.%u.%u dst=%u.%u.%u.%u sport=%u dport=%u, %smark=%u use=%u\n",
                                  TIME_ARG(tm),
                                  prot, type, state,
                                  ip_src[0], ip_src[1], ip_src[2], ip_src[3],
                                  ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3],
                                  ntohs(src.src.u.tcp.port), ntohs(src.dst.u.tcp.port),
                                  orig_state,
                                  rep_src[0], rep_src[1], rep_src[2], rep_src[3],
                                  rep_dst[0], rep_dst[1], rep_dst[2], rep_dst[3],
                                  ntohs(dst.src.u.tcp.port), ntohs(dst.dst.u.tcp.port),
                                  rep_state,
                                  mark, use);
        }
    }
    case AF_INET6:  {
        char ip6_addr[4][INET6_ADDRSTRLEN];

        switch(src.dst.protonum)  {
        case IPPROTO_TCP:
            prot = "TCP";
            if(! nfct_conn_get_tcpinfo(ent, &tcpinfo))  {
                if(tcpinfo.state >= TCP_CONNTRACK_MAX)
                    state = "[INVALID] ";
                else
                    state = tcp_state_tbl[tcpinfo.state];
            }
            break;
        case IPPROTO_UDP:
            prot = "UDP";
            if(! (ent->status & IPS_SEEN_REPLY))
                orig_state = "[UNREPLIED] ";
            if(ent->status & IPS_ASSURED)
                rep_state = "[ASSURED] ";
            break;
        case IPPROTO_UDPLITE:
            prot = "UDPlite";
            if(! (ent->status & IPS_SEEN_REPLY))
                orig_state = "[UNREPLIED] ";
            if(ent->status & IPS_ASSURED)
                rep_state = "[ASSURED] ";
            break;
        case IPPROTO_ICMP:
            prot = "ICMP";
            if(! (ent->status & IPS_SEEN_REPLY))
                orig_state = "[UNREPLIED] ";
            if(ent->status & IPS_ASSURED)
                rep_state = "[ASSURED] ";
            break;
        default:
            sprintf(protonum, "[%u]", src.src.l3num);
            prot = protonum;
            break;
        }
        if(counter_avail)  {
            return gardenia_print(log_pool[LOG_CONNTRACK], TIME_FORMAT "IPv6 %s %s%ssrc=%s dst=%s sport=%u dport=%u "
                                  "pkts=%llu bytes=%llu %ssrc=%s dst=%s sport=%u dport=%u "
                                  "pkts=%llu bytes=%llu, %smark=%u use=%u\n",
                                  TIME_ARG(tm),
                                  prot, type, state,
                                  inet_ntop(AF_INET6, src.src.u3.ip6, ip6_addr[0], INET6_ADDRSTRLEN) ? : "<INVALID>",
                                  inet_ntop(AF_INET6, src.dst.u3.ip6, ip6_addr[1], INET6_ADDRSTRLEN) ? : "<INVALID>",
                                  ntohs(src.src.u.tcp.port), ntohs(src.dst.u.tcp.port),
                                  counter.orig_pkts, counter.orig_bytes,
                                  orig_state,
                                  inet_ntop(AF_INET6, dst.src.u3.ip6, ip6_addr[2], INET6_ADDRSTRLEN) ? : "<INVALID>",
                                  inet_ntop(AF_INET6, dst.dst.u3.ip6, ip6_addr[3], INET6_ADDRSTRLEN) ? : "<INVALID>",
                                  ntohs(dst.src.u.tcp.port), ntohs(dst.dst.u.tcp.port),
                                  counter.rep_pkts, counter.rep_bytes,
                                  rep_state,
                                  mark, use);
        }else  {
            return gardenia_print(log_pool[LOG_CONNTRACK], TIME_FORMAT "IPv6 %s %s%ssrc=%s dst=%s sport=%u dport=%u "
                                  "%ssrc=%s dst=%s sport=%u dport=%u, %smark=%u use=%u\n",
                                  TIME_ARG(tm),
                                  prot, type, state,
                                  inet_ntop(AF_INET6, src.src.u3.ip6, ip6_addr[0], INET6_ADDRSTRLEN) ? : "<INVALID>",
                                  inet_ntop(AF_INET6, src.dst.u3.ip6, ip6_addr[1], INET6_ADDRSTRLEN) ? : "<INVALID>",
                                  ntohs(src.src.u.tcp.port), ntohs(src.dst.u.tcp.port),
                                  orig_state,
                                  inet_ntop(AF_INET6, dst.src.u3.ip6, ip6_addr[2], INET6_ADDRSTRLEN) ? : "<INVALID>",
                                  inet_ntop(AF_INET6, dst.dst.u3.ip6, ip6_addr[3], INET6_ADDRSTRLEN) ? : "<INVALID>",
                                  ntohs(dst.src.u.tcp.port), ntohs(dst.dst.u.tcp.port),
                                  rep_state,
                                  mark, use);
        }
    }
    default:
        return gardenia_print(log_pool[LOG_CONNTRACK], TIME_FORMAT "UNKNOWN AF:%u\n",
                              TIME_ARG(tm), src.src.l3num);
    }
}

static int __log_conntrack(nfct_msg *msg, time_t *tick)
{
    list fos = LIST_HEAD_INIT(fos);
    int res = 0, tmp;
    time_t t = tick ? *tick : time(NULL);

    assert(msg && msg->entry);
    if(! lookup_fos_from_ct(&fos, msg))  {
        res = __log_fos(&fos);
        fd_owners_free(&fos);
        PR_DEBUG("success looking up fos");
    }else  {
        PR_DEBUG("fail to look up fos");
    }

    tmp = __do_log_conntrack(msg, &t);
    if(tmp > 0)
        res += tmp;
    return res;
}

static int __log_conntrack_info(conntrack_info *ci)
{
    int res, tmp;
    time_t t = time(NULL);

    assert(ci && ci->ct);
    if(! ci->ls)
        return __log_conntrack(ci->ct, &t);

    res = __log_fos(ci->ls);
    tmp = __do_log_conntrack(ci->ct, &t);
    if(tmp > 0)
        res += tmp;
    return res;
}

int cactus_log(int lvl, int type, void *obj)
{
    int res = -1;

    if(log_init && type >= 0 && type < NUM_LOG && log_ctl[type] && obj)  {
        if(type >= 0 && type < NUM_LOG)
            pthread_mutex_lock(&log_lock[type]);
        switch(type)  {
        case LOG_MAIN:
            if(lvl >= 0 && lvl < NUM_LVL && log_mask[lvl])
                res = __log_main(lvl, (const char *)obj);
            break;
        case LOG_RTNL:
            res = __log_rtnl((rtnl_msg *)obj);
            break;
        case LOG_UEVENT:
            res = __log_uevent((uevent_msg *)obj);
            break;
        case LOG_CONNTRACK:
            res = __log_conntrack_info((conntrack_info *)obj);
            break;
        default:
            cactus_log_printf(LOG_DEBUG, "invalid log type:%d", type);
            break;
        }
        if(type >= 0 && type < NUM_LOG)
            pthread_mutex_unlock(&log_lock[type]);
    }
    return res;
}

int cactus_log_printf(int lvl, const char *fmt, ...)
{
    va_list ap;
    char *s;
    int res = -1;

    if(log_init
       && log_ctl[LOG_MAIN]
       && lvl >= 0
       && lvl < NUM_LVL
       && log_mask[lvl])  {
        va_start(ap, fmt);
        if(vasprintf(&s, fmt, ap) > 0)  {
            pthread_mutex_lock(&log_lock[LOG_MAIN]);
            res = __log_main(lvl, s);
            pthread_mutex_unlock(&log_lock[LOG_MAIN]);
            free(s);
        }
        va_end(ap);
    }
    return res;
}


#define __DUMP_RTNL()                       \
    list_for_each_rtnl_msg(m, &dump)  {     \
        __log_rtnl_msg(m);                  \
    }list_end


static void on_rtnl_enabled(void)
{
    list dump;
    rtnl_msg *m;

    LOG_INFO("init dump RTNL");
    pthread_mutex_lock(&log_lock[LOG_RTNL]);
    __log_rtnl_ts();
    if(! rtnl_dump_link(&dump, 0))  {
        __DUMP_RTNL();
    }
    rtnl_msg_list_free(&dump);

    __log_rtnl_ts();
    if(! rtnl_dump_addr(&dump, AF_INET))  {
        __DUMP_RTNL();
    }
    rtnl_msg_list_free(&dump);

    __log_rtnl_ts();
    if(! rtnl_dump_addr(&dump, AF_INET6))  {
        __DUMP_RTNL();
    }
    rtnl_msg_list_free(&dump);

    __log_rtnl_ts();
    if(! rtnl_dump_route_inet(&dump))  {
        __DUMP_RTNL();
    }
    rtnl_msg_list_free(&dump);

    __log_rtnl_ts();
    if(! rtnl_dump_rule(&dump, AF_INET))  {
        __DUMP_RTNL();
    }
    rtnl_msg_list_free(&dump);

    __log_rtnl_ts();
    if(! rtnl_dump_neigh(&dump, AF_INET, 0))  {
        __DUMP_RTNL();
    }
    rtnl_msg_list_free(&dump);
    pthread_mutex_unlock(&log_lock[LOG_RTNL]);
}

static void on_conntrack_enabled(nfct_t *ct)
{
    list dump;
    nfct_msg *m;
    time_t t = time(NULL);

    LOG_INFO("init dump CONNTRACK");
    pthread_mutex_lock(&log_lock[LOG_CONNTRACK]);
    if(! nfct_dump_conn(ct, &dump, AF_INET, 0))  {
        list_for_each_nfct_msg(m, &dump)  {
            if(! core_nfct_filtered(m))
                __log_conntrack(m, &t);
        }list_end;
    }
    nfct_msg_list_free(&dump);

    if(! nfct_dump_conn(ct, &dump, AF_INET6, 0))  {
        list_for_each_nfct_msg(m, &dump)  {
            if(! core_nfct_filtered(m))
                __log_conntrack(m, &t);
        }list_end;
    }
    nfct_msg_list_free(&dump);
    pthread_mutex_unlock(&log_lock[LOG_CONNTRACK]);
}

void cactus_log_set_ctl(int log, int enabled)
{
    switch(log)  {
    case LOG_MAIN:
        if(log_ctl[LOG_MAIN] != !! enabled)  {
            LOG_INFO("LOG_MAIN toggle %s", enabled ? "enabled" : "disabled");
            log_ctl[LOG_MAIN] = !! enabled;
            LOG_INFO("LOG_MAIN toggle %s", enabled ? "enabled" : "disabled");
        }
        break;
    case LOG_RTNL:
        if(log_ctl[LOG_RTNL] != !! enabled)  {
            LOG_INFO("LOG_RTNL toggle %s", enabled ? "enabled" : "disabled");
            if((log_ctl[LOG_RTNL] = !! enabled))
                on_rtnl_enabled();
        }
        break;
    case LOG_UEVENT:
        if(log_ctl[LOG_UEVENT] != !! enabled)  {
            LOG_INFO("LOG_UEVENT toggle %s", enabled ? "enabled" : "disabled");
            log_ctl[LOG_UEVENT] = !! enabled;
        }
        break;
    case LOG_CONNTRACK:
        if(log_ctl[LOG_CONNTRACK] != !! enabled)  {
            LOG_INFO("LOG_CONNTRACK toggle %s", enabled ? "enabled" : "disabled");
            if((log_ctl[LOG_CONNTRACK] = !! enabled))
                on_conntrack_enabled(core_nfct());
        }
        break;
    default:
        LOG_ERROR("invalid log to set ctl:%d", log);
        break;
    }
}

void cactus_log_flush(void)
{
    int i;

    for(i = 0; i < NUM_LOG; i++)  {
        if(log_pool[i])  {
            gardenia_flush(log_pool[i]);
        }
    }
}

