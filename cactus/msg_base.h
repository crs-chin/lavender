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


#ifndef __MSG_BASE_H
#define __MSG_BASE_H

#include <time.h>
#include <stdint.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <sys/types.h>

#include "linux_netfilter_nf_conntrack_tuple_common.h"

#define CACTUS_SERVER_ABSTRACT 1
#define CACTUS_SERVER_MAX_PEER 5
#define CACTUS_SERVER_PATH  "/var/run/cactus/socket"

#define CACTUS_GROUP_NAME "cactus"

#define CACTUS_SVC_NAME "Cactus Runtime"

__BEGIN_DECLS

typedef struct _msg_fe_register msg_fe_register;     /* rpc req */
typedef struct _msg_fe_unregister msg_fe_unregister; /* rpc req */
typedef struct _msg_rule_req msg_rule_req;           /* rpc req */
typedef struct _msg_core_status msg_core_status;     /* rpc rsp */
typedef struct _msg_core_version msg_core_version;   /* rpc rsp */
typedef struct _msg_log_ctl msg_log_ctl;             /* rpc req */
typedef struct _msg_log_stat msg_log_stat;           /* rpc rsp */
typedef struct _msg_verdict_req msg_verdict_req;     /* unsol msg */
typedef struct _msg_verdict_res msg_verdict_res;     /* unsol msg */
typedef struct _msg_runtime_info msg_runtime_info;   /* unsol msg */

typedef struct _msg_fd_owner msg_fd_owner;

/* defined logs */
enum{
    LOG_MAIN,
    LOG_RTNL,
    LOG_UEVENT,
    LOG_CONNTRACK,

    NUM_LOG,
};

enum{
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_EMERG,
    LOG_ERROR,
    LOG_FATAL,

    NUM_LVL,
};

struct _msg_fe_register{
    unsigned int peer;
};


struct _msg_fe_unregister{
    unsigned int peer;
};

struct _msg_rule_req{
    char path[0];
};

#define STATUS_INACTIVE 0
#define STATUS_ACTIVE 1

struct _msg_core_status{
    int status;
};

struct _msg_core_version{
    int version;
    unsigned int len;
    char banner[0];
};

struct _msg_log_ctl{
    int ctl[NUM_LOG];
    int mask[NUM_LVL];
};

struct _msg_log_stat{
    int ctl[NUM_LOG];
    int mask[NUM_LVL];
};

struct _msg_fd_owner{
    uid_t euid, egid;
    pid_t pid, ppid, tgid, tracerpid, sid;
    char exe[0];
};

struct _msg_verdict_req{
    uint64_t id;
    /* monotonic timeout ts */
    struct timespec ts;
    int fo_count;
    msg_fd_owner fos[0];
};

enum{
    INFO_MSG,                  /* runtime related info for front-end
                                   display */
};

struct _msg_runtime_info{
    int type;
    time_t time;
    int len;
    char info[0];
};

#define msg_fd_owner_for_each(fo,msg)                                   \
    {int __i = 0;                                                       \
    for(fo = &(msg)->fos[0];__i < (msg)->fo_count;                      \
        fo = (typeof(fo))((char *)fo + sizeof(*fo) + strlen(fo->exe) + 1), __i++) \

#ifndef list_end
#define list_end }
#endif

/* program restart count as once, as only as pid unchanged */
enum{
    VERDICT_NONE,
    VERDICT_QUERY,
    VERDICT_ALLOW_ONCE,         /* fall back into VERDICT_QUERY after once */
    VERDICT_ALLOW_ALWAYS,
    VERDICT_DENY_ONCE,          /* fall back into VERDICT_QUERY after once */
    VERDICT_DENY_ALWAYS,
    VERDICT_KILL_ONCE,          /* fall back into VERDICT_QUERY after once */
    VERDICT_KILL_ALWAYS,

    NUM_VERDICT,
};

struct _msg_verdict_res{
    uint64_t id;
    int verdict;
};

/* error messages */
#define CACTUS_ERR_OK 0
#define CACUS_ERR_BASE (-100)
#define CACTUS_ERR_GENERIC (-1 + CACUS_ERR_BASE)
#define CACTUS_ERR_UNKNOWN_REQ (-2 + CACUS_ERR_BASE)
#define CACTUS_ERR_ALREADY_REGISTERED (-3 + CACUS_ERR_BASE)
#define CACTUS_ERR_BAD_PARM (-4 + CACUS_ERR_BASE)
#define CACTUS_ERR_NO_SUCH_PEER (-5 + CACUS_ERR_BASE)
#define CACTUS_ERR_NOT_REGISTERED (-6 + CACUS_ERR_BASE)

/* defined to RPCLITE_REQ_BASE */
#define CACTUS_REQ_BASE 100

enum{
    CACTUS_REQ_REGISTER_FE = CACTUS_REQ_BASE,
    CACTUS_REQ_UNREGISTER_FE,

    CACTUS_REQ_RULE_LOAD,
    CACTUS_REQ_RULE_DUMP,

    CACTUS_REQ_CORE_ACTIVATE,
    CACTUS_REQ_CORE_DEACTIVATE,
    CACTUS_REQ_CORE_STATUS,
    CACTUS_REQ_CORE_VERSION,

    CACTUS_REQ_LOG_FLUSH,
    CACTUS_REQ_LOG_CONTROL,
    CACTUS_REQ_LOG_STATE,

    CACTUS_REQ_CORE_EXIT,
};

#define CACTUS_REQ_FW_BASE (CACTUS_REQ_BASE + 1000)

typedef struct _msg_counter_status msg_counter_status;
typedef struct _msg_fw_table_state msg_fw_table_state;
typedef struct _msg_throttle_req msg_throttle_req;
typedef struct _msg_throttle_res msg_throttle_res;
typedef struct _msg_query_nw_req msg_query_nw_req;
typedef struct _msg_nw_connection msg_nw_connection;
typedef struct _msg_nw_counter msg_nw_counter;
typedef struct _msg_query_fw_req msg_query_fw_req;
typedef struct _msg_prog_res msg_prog_res;
typedef struct _msg_user_res msg_user_res;
typedef struct _msg_proc_res msg_proc_res;
typedef struct _msg_cfg_rule_req msg_cfg_rule_req;

enum{
    CMD_SET,
    CMD_QUERY,
};

struct _msg_counter_status{
    int cmd;
    int status;
};

struct _msg_fw_table_state{
    size_t connections;
    size_t programs;
    size_t processes;
    size_t users;
};

enum{
    THROTTLE_CONN,
    THROTTLE_PROC,
    THROTTLE_PROG,
    THROTTLE_USER,
};

typedef struct _conn_parm conn_parm;

struct _conn_parm{
    struct{
        union nf_inet_addr u3;
        union nf_conntrack_man_proto u;
        __u16 l3num;            /* currently AF_INET or AF_INET6 */
    }src;
    struct{
        union nf_inet_addr u3;
        union {
            /* Add other protocols here. */
            __be16 all;
            struct {
                __be16 port;
            } tcp;
            struct {
                __be16 port;
            } udp;
            struct {
                __u8 type, code;
            } icmp;
            struct {
                __be16 port;
            } dccp;
            struct {
                __be16 port;
            } sctp;
            struct {
                __be16 key;
            } gre;
        } u;
        __u8 protonum;          /* tcp, udp and etc. */
    }dst;
};

struct _msg_throttle_req{
    int cmd;
    int type;
    int enabled;
    union{
        struct{
            __u16 zone;
            conn_parm conn_parm;
        };
        pid_t pid;
        uid_t uid;
    };
    char path[0];
};

struct _msg_throttle_res{
    int type;
    int enabled;
};

enum{
    TYPE_CONN,    /* nw counter only */
    TYPE_PROC,
    TYPE_PROG,
    TYPE_USER,
    TYPE_GLOBAL,    /* nw counter only */
};

struct _msg_query_nw_req{
    int type;
    union{
        struct{
            __u16 zone;
            conn_parm conn_parm;
        };
        pid_t pid;
        uid_t uid;
    };
    char path[0];
};

struct _msg_nw_connection{
    __u16 zone;
    conn_parm conn_parm;
    /* ?? more connection info */
};

struct _msg_nw_counter{
    __u64 orig_pkts;
    __u64 orig_bytes;
    __u64 rep_pkts;
    __u64 rep_bytes;
};

enum{
    BY_NONE,
    BY_PROG,
    BY_USER,
};

struct _msg_query_fw_req{
    int type;
    union{
        /* used for query prog or user */
        int active_only;
        /* used for proc query */
        int by_which;
    };
    uid_t uid;
    char path[0];
};

/* sequence dependent, don't change it */
enum{
    FW_ACCEPT,             /* accepted, but still check the following
                              kernel rules */
    FW_STOP,               /* accepted, reinject into NW stack */
    FW_VERDICT,            /* query front-end */
    FW_DROP,               /* packet dropped */
    FW_KILL,               /* terminate process */
};

#define TARGET_MASK  0x00FF
#define VERDICT_SHIFT 16

struct _msg_prog_res{
    uid_t uid;
	int action;
    char path[0];
};

struct _msg_user_res{
    uid_t uid;
	char name[0];
};

struct _msg_proc_res{
    pid_t pid;
	uid_t uid;
	int action;
	char exe[0];
};

struct _msg_cfg_rule_req{
    int cmd;
    int action;
    msg_query_nw_req query;
};

/* for CMD_QUERY only */
struct _msg_cfg_rule_res{
    int action;
};

enum{
    CACTUS_REQ_COUNTER_STATUS = CACTUS_REQ_FW_BASE,

    CACTUS_REQ_FW_TABLE_STATE,

    /* cactus will resent all pending verdicts */
    CACTUS_REQ_REFRESH_VERDICT,

    /* immediate control on network connections */
    CACTUS_REQ_THROTTLE_CONNECTION,

    CACTUS_REQ_QUERY_NW_CONNECTION,
    CACTUS_REQ_QUERY_NW_COUNTER,

    CACTUS_REQ_QUERY_FW_OBJECT,

    CACTUS_REQ_CFG_FW_RULE,
};

#define CACTUS_REQ_TEST_BASE (CACTUS_REQ_BASE + 2000)

typedef struct _msg_test_res msg_test_res;

struct _msg_test_res{
    char res[0];
};

enum{
    CACTUS_REQ_MAKE_TEST = CACTUS_REQ_TEST_BASE,
};

/* defined to IPCLITE_MSG_BASE */
#define CACTUS_MSG_BASE  1000

#define CACTUS_VERDICT_BASE (CACTUS_MSG_BASE + 100)

enum{
    CACTUS_VERDICT_REQUEST = CACTUS_VERDICT_BASE,
    CACTUS_VERDICT_RESULT,

    CACTUS_RUNTIME_INFO,
};

#define RANGE_CACTUS_VERDICT 2

__END_DECLS

#endif  /* __MSG_BASE_H */

