/*
 * lotus.c CLI console for Cactus Runtime.
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

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <time.h>
#include <arpa/inet.h>
#ifndef ANDROID_CHANGES
#include <readline/readline.h>
#include <readline/history.h>
#else
/* not defined on android */
enum  {
    IPPROTO_UDPLITE = 136, /* UDP-Lite protocol.  */
#define IPPROTO_UDPLITE		IPPROTO_UDPLITE
};
#endif

#include "desert.h"

#define ERROR(fmt,args...) do{fprintf(stderr, fmt "\n", ##args); exit(-1);}while(0)
#define ERROR_RET(err,fmt,args...) do{fprintf(stderr, fmt "\n", ##args); return err;}while(0)

#define TOKS_MIN 10

typedef struct _verdict_record verdict_record;
typedef struct _command_desc command_desc;
typedef struct _nw_conn nw_conn;
typedef struct _nw_conn_ctx nw_conn_ctx;

struct _verdict_record{
    verdict_record *next;
    msg_verdict_req req[0];
};

struct _command_desc{
    char *cmd;
    char *desc;
    void (*func)(char *args[], const command_desc *cmd);
    const char *(*get_help)(const char *cmd);
};

struct _nw_conn{
    list list;
    uint64_t seq;
    msg_nw_connection conn;
};

struct _nw_conn_ctx{
    list head;
    uint64_t seq;
};

static const char banner[] = "Lotus, The Lavender CLI console";

static pthread_mutex_t record_lock = PTHREAD_MUTEX_INITIALIZER;
static verdict_record *record_list = NULL;
static verdict_record *record_end = NULL;
static int front_end = 0;
static list conn_head = LIST_HEAD_INIT(conn_head);

static void cmd_list(char *args[], const command_desc *cmd);
static void cmd_verd(char *args[], const command_desc *cmd);
static void cmd_exit(char *args[], const command_desc *cmd);
static void cmd_help(char *args[], const command_desc *cmd);
static void cmd_get(char *args[], const command_desc *cmd);
static void cmd_set(char *args[], const command_desc *cmd);
static void cmd_shutdown(char *args[], const command_desc *cmd);
static void cmd_flush(char *args[], const command_desc *cmd);
static void cmd_rule(char *args[], const command_desc *cmd);

static const char *get_help(const char *cmd);

static const command_desc cmd_tbl[] = {
    {"list", "list fw objects and etc.", cmd_list, get_help},
    {"verd", "verdict the request", cmd_verd, get_help},
    {"exit", "exit command shell", cmd_exit, NULL},
    {"get", "get lavender specific config or state", cmd_get, get_help},
    {"set", "set lavender specific config or state", cmd_set, get_help},
    {"shutdown", "shutdown lavender service and exit", cmd_shutdown, NULL},
    {"flush", "flush lavender service logs", cmd_flush, NULL},
    {"rule", "control lavender service logs", cmd_rule, get_help},
    {"help", "show help message", cmd_help, NULL},
    {NULL, NULL, NULL, NULL},
};

static const struct{
    char *cmd;
    int verd;
}verdict_cmd[] = {
    {"none", VERDICT_NONE},
    {"allow", VERDICT_ALLOW_ONCE,},
    {"allow_always", VERDICT_ALLOW_ALWAYS, },
    {"deny", VERDICT_DENY_ONCE, },
    {"deny_always", VERDICT_DENY_ALWAYS, },
    {"kill", VERDICT_KILL_ONCE, },
    {"kill_always", VERDICT_KILL_ALWAYS, },
};

static const char *target_tbl[] = {
    "ACCEPT",
    "REINJECT",
    "VERDICT",
    "DROP",
    "KILL",
};

static const char *verdict_tbl[] = {
    "NONE",
    "VERDICT",
    "ALLOW ONCE",
    "ACCEPT",
    "DENY ONCE",
    "DROP",
    "KILL ONCE",
    "KILL",
};

static const char *log_tbl[] = {
    "main", "rtnl", "uevent", "conntrack",
};

static const char *level_tbl[] = {
    "debug", "info", "warn", "emerg", "error", "fatal",
};

enum{
    CMD_NONE,
    CMD_LOAD,
    CMD_DUMP,
    CMD_STATUS,
    CMD_FLUSH_LOGS,
    CMD_LOG_CONTROL,
    CMD_LEVEL_CONTROL,
    CMD_CACTUS_CONTROL,
    CMD_SHUTDOWN,
    CMD_SHELL,
    CMD_COMMAND,
    CMD_VERSION,
    CMD_TEST,
};

static void help(const char *prog)
{
    printf("  %s\nUSAGE:\n%s OPTIONS\n"
           "  -l|--load PATH    Load rules from PATH\n"
           "  -f|--flush        Flush rules\n"
           "  -d|--dump PATH    Dump rules into PATH\n"
           "  -u|--status       Print lavender status\n"
           "  -s|--state on|off Specify target state\n"
           "  -g|--log <TYPE>   Specify log type to operate\n"
           "  -c|--cactus       Specify cactus state to operate\n"
           "  -L|--level <LVL>  Specify log level to operate\n"
           "  -h|--help         Show this help message\n"
           "  -S|--shutdown     Shutdown Cactus Runtime\n"
           "  -t|--shell        Run in lotus shell mode\n"
           "  -C|--command      Run lotus shell command\n"
           "  -v|--version      Show version info\n"
           "TYPE: main, rtnl, uevent, conntrack, all\n"
           "LVL: debug, info, warn, emerg, error, fatal, all\n"
           "EXAMPLES:\n"
           "  # enable uevent log\n"
           "  %s -s on -g uevent\n"
           "  # enable debug level log\n"
           "  %s -s on -L debug\n"
           "  # turn on cactus\n"
           "  %s -s on -c\n",
           banner, prog, prog, prog, prog);
}

static const char *get_help(const char *cmd)
{
    const char *msg = "  <no help message>";

    if(! strcasecmp(cmd, "list"))  {
        msg = "  list Cactus fw objects\n"
            "    list [ARGUMENTS]\n"
            "  ARGUMENTS:\n"
            "    verd               show pending verdicts\n"
            "    prog  [OPT]        show fw recorded progs\n"
            "     OPT:\n"
            "     active            show only active progs\n"
            "    proc  <OPT>        show fw recorded processes\n"
            "     OPT:\n"
            "     prog <PATH>       show processes of prog specified\n"
            "     user <UID>        show processes of uid specified\n"
            "    user  [OPT]        show fw recorded users\n"
            "     OPT:\n"
            "     active            show only active users\n"
            "    conn <OPT>         show fw recorded connections\n"
            "     OPT:\n"
            "     proc <PID>        show connections of pid specified\n"
            "     prog <PATH> <UID> show connections of prog specified\n"
            "     user <UID>        show connections of uid specified";
    }else if(! strcasecmp(cmd, "verd"))  {
        msg = "  verdict the last verdict request\n"
            "    verd [TARGET]\n"
            "  TARGET:\n"
            "    none               silently ignore this verdict\n"
            "    allow              allow for this time\n"
            "    allow_always       allow always\n"
            "    deny               deny for this time\n"
            "    deny_always        deny always\n"
            "    kill               kill for this time\n"
            "    kill_always        always kill";
    }else if(! strcasecmp(cmd, "get"))  {
        msg = "  get lavender service config and state\n"
            "    get [ARGUMENTS]\n"
            "  ARGUMENTS:\n"
            "    logtype <TYPE>     show log type enable status\n"
            "     TYPE:\n"
            "     main, rtnl, uevent, conntrack, all\n"
            "    loglevel <LEVEL>   show log level enable status\n"
            "     LEVEL:\n"
            "     debug, info, warn, emerg, error, fatal, all\n"
            "    action <OBJ>       show fw object rule action\n"
            "     OBJ:\n"
            "     proc <PID>        show proc object rule action\n"
            "     prog <PATH> <UID> show prog object rule action\n"
            "    throttle <OBJ>     show fw object throttle status\n"
            "     OBJ:\n"
            "     conn <CONN_ID>    show connection throttle status\n"
            "     proc <PID>        show proc throttle status\n"
            "     prog <PATH> <UID> show prog throttle status\n"
            "    counter <OBJ>      show fw object conntrack counter info\n"
            "     OBJ:\n"
            "     conn <CONN_ID>    show connection counter info\n"
            "     proc <PID>        show proc counter info\n"
            "     prog <PATH> <UID> show prog counter info\n"
            "     user <UID>        show user counter info\n"
            "    state              show current cactus status\n"
            "    version            show service version info";
    }else if(! strcasecmp(cmd, "set"))  {
        msg = "  set lavender service config and state\n"
            "    set [ARGUMENTS]\n"
            "  ARGUMENTS:\n"
            "    front-end <on|off>        set front-end mode on or off\n"
            "    state <on|off>            set cactus status on or off\n"
            "    logtype <TYPE> <on|off>   set log type on or off\n"
            "     TYPE:\n"
            "     main, rtnl, uevent, conntrack, all\n"
            "    loglevel <LEVEL> <on|off> set log level on or off\n" 
            "     LEVEL:\n"
            "     debug, info, warn, emerg, error, fatal, all\n"
            "    action <OBJ> <ACT>        set fw object rule action\n"
            "     OBJ:\n"
            "     proc <PID>               set proc object rule action\n"
            "     prog <PATH> <UID>        set prog object rule action\n"
            "     ACT:\n"
            "     allow, allow_always, deny, deny_always, kill, kill_always\n"
            "    throttle <OBJ> <on|off>   set fw object throttle status\n"
            "     OBJ:\n"
            "     conn <CONN_ID>           set connection throttle status\n"
            "     proc <PID>               set proc throttle status\n"
            "     prog <PATH> <UID>        set prog throttle status";
    }else if(! strcasecmp(cmd, "rule"))  {
        msg = "  control lavender service rule dbase\n"
            "    rule [ARGUMENTS]\n"
            "  ARGUMENTS:\n"
            "    dump <PATH>    dump rules to path\n"
            "    load <PATH>    load rules from path";
    }

    return msg;
}

static inline void set_cmd(int *var, int cmd)
{
    if(*var != CMD_NONE)
        ERROR("Ambiguous command.");
    *var = cmd;
}

#define SET_CMD(command) set_cmd(&cmd, CMD_##command)
#define SET_ARG() do{if(! optarg || ! *optarg) ERROR("Argument required."); arg = optarg;}while(0)

static void on_connect_cb(int state, unsigned int peer, void *ud)
{
    if(! state)
        ERROR("Passively disconencted from server!\n");
}

static inline int ts_cmp(const struct timespec *a, const struct timespec *b)
{
    if(a->tv_sec < b->tv_sec)
        return -1;
    else if(a->tv_sec > b->tv_sec)
        return 1;
    if(a->tv_nsec < b->tv_nsec)
        return -1;
    else if(a->tv_nsec > b->tv_nsec)
        return 1;
    return 0;
}

static void on_verdict_req(const msg_verdict_req *req)
{
    static unsigned int seq = 0;
    const msg_fd_owner *fo;
    verdict_record *r;
    struct timespec ts;
    size_t sz = sizeof(*req);
    int timeout;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    /* ignore already expired ones */
    if(ts_cmp(&ts, &req->ts) >= 0)
        return;

    timeout = req->ts.tv_sec - ts.tv_sec;
    if(req->ts.tv_nsec - ts.tv_nsec > 500000000)
        timeout++;

    printf("\n[%u]  VERDICT REQUEST, ID:%llu, TIMEOUT:%d\n", seq++, req->id, timeout);
    msg_fd_owner_for_each(fo, req)  {
        printf("    UID:%u, PID:%u, EXE:%s\n", fo->euid, fo->pid, fo->exe);
        sz += sizeof(*fo) + strlen(fo->exe) + 1;
    }list_end;

    if((r = (verdict_record *)malloc(sizeof(*r) + sz)))  {
        r->next = NULL;
        memcpy(&r->req, req, sz);
        pthread_mutex_lock(&record_lock);
        if(! record_list)  {
            record_list = r;
            record_end = r;
        }else  {
            record_end->next = r;
            record_end = r;
        }
        pthread_mutex_unlock(&record_lock);
    }
}

static void on_runtime_info(const msg_runtime_info *info)
{
    switch(info->type)  {
    case INFO_MSG:
        printf("\n[INFO]%s %.*s\n", ctime(&info->time), info->len, info->info);
        break;
    default:
        printf("Unrecognized runtime info type received:%u, ignored", info->type);
        break;
    }
}

static void fe_cb(int type, const void *msg, void *ud)
{
    switch(type)  {
    case CACTUS_VERDICT_REQUEST:  {
        on_verdict_req((const msg_verdict_req *)msg);
        break;
    }
    case CACTUS_RUNTIME_INFO:  {
        on_runtime_info((const msg_runtime_info *)msg);
        break;
    }
    default:  {
        printf("Unrecognized fe message received:%u, ignored", type);
        break;
    }
    }
}

static void __list_verd(void)
{
    verdict_record *r;
    msg_verdict_req *req;
    msg_fd_owner *fo;
    struct timespec ts;
    int timeout, seq = 0;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    for(r = record_list; r; r = r->next)  {
        req = &r->req[0];

        timeout = req->ts.tv_sec - ts.tv_sec;
        if(req->ts.tv_nsec - ts.tv_nsec > 500000000)
            timeout++;

        if(ts_cmp(&ts, &req->ts) >= 0)
            timeout = -1;

        if(timeout > 0)
            printf("[%u]  VERDICT REQUEST, ID:%llu, TIMEOUT:%d\n", seq++, req->id, timeout);
        else
            printf("[%u]  VERDICT REQUEST, ID:%llu, OUTDATED\n", seq++, req->id);
        msg_fd_owner_for_each(fo, req)  {
            printf("    UID:%u, PID:%u, EXE:%s\n", fo->euid, fo->pid, fo->exe);
        }list_end;
    }
}

static void list_verd(void)
{
    pthread_mutex_lock(&record_lock);
    if(! front_end)  {
        printf("Not in front-end mode!\n");
    }else  {
        if(record_list)
            printf("VERDICT LIST:\n");
        else
            printf("No pending Verdicts.\n");
        __list_verd();
    }
    pthread_mutex_unlock(&record_lock);
}

static const char *action_string(int action)
{
    int target = ACTION_TARGET(action);
    int verdict = ACTION_VERDICT(action);

    if(target < 0 || (unsigned)target >= arraysize(target_tbl))
        return "<INVALID ACTION>";
    if(target == FW_VERDICT)  {
        if(verdict < 0 || (unsigned)verdict >= arraysize(verdict_tbl))
            return "<INVALID VERDICT>";
        return verdict_tbl[verdict];
    }
    return target_tbl[target];
}

static void list_prog(char *args[])
{
    int seq = 0, flags = 0;
    fw_obj *obj;
    msg_prog_res *res;
    list progs;

    if(args[0] && args[0][0])  {
        if(! strcasecmp(args[0], "active"))  {
            flags = ITER_F_ACTIVE;
        }else  {
            printf("Unrecognized argument \"%s\"\n", args[0]);
            return;
        }
    }

    desert_get_all_fw_progs(&progs, flags);

    if(list_empty(&progs))  {
        printf("No records returned!\n");
        return;
    }

    printf("INDEX UID        ACTION          PATH\n");
    list_for_each_entry(obj, &progs, list)  {
        res = &obj->prog[0];
        printf("[%d]   %-10u %-15s %s\n", seq++, res->uid, action_string(res->action), res->path);
    }
    fw_objs_free(&progs);
}

static void list_user(char *args[])
{
    int seq = 0, flags = 0;
    fw_obj *obj;
    msg_user_res *res;
    list users;

    if(args[0] && args[0][0])  {
        if(! strcasecmp(args[0], "active"))  {
            flags = ITER_F_ACTIVE;
        }else  {
            printf("Unrecognized argument \"%s\"\n", args[0]);
            return;
        }
    }

    desert_get_all_fw_users(&users, flags);

    if(list_empty(&users))  {
        printf("No records returned!\n");
        return;
    }

    printf("INDEX UID        NAME\n");
    list_for_each_entry(obj, &users, list)  {
        res = &obj->user[0];
        printf("[%d]   %-10u %s\n", seq++, res->uid, res->name);
    }
    fw_objs_free(&users);
}

static void list_proc(char *args[])
{
    int seq = 0;
    msg_proc_res *res;
    fw_obj *obj;
    list procs;

    if(args[0] && args[0][0])  {
        if(! strcasecmp(args[0], "prog"))  {
            if(! args[1] || ! args[1][0])  {
                printf("Parameter \"prog\" requires an argument, abort!\n");
                return;
            }
            desert_get_all_procs_of_prog(&procs, args[1]);
        }else if(! strcasecmp(args[0], "user"))  {
            char *endp;
            uid_t uid;

            if(! args[1] || ! args[1][0])  {
                printf("Parameter \"user\" requires an argument, abort!\n");
                return;
            }
            uid = strtol(args[1], &endp, 0);
            if(*endp)  {
                printf("Not a valid UID \"%s\", abort!\n", args[1]);
                return;
            }
            desert_get_all_procs_of_user(&procs, uid);
        }else  {
            printf("Invalid argument \"%s\", abort!\n", args[0]);
            return;
        }
    }else  {
        desert_get_all_fw_procs(&procs);
    }

    if(list_empty(&procs))  {
        printf("No records returned!\n");
        return;
    }

    printf("INDEX PID      UID      ACTION       PATH\n");
    list_for_each_entry(obj, &procs, list)  {
        res = &obj->proc[0];
        printf("[%d]   %-8u %-8u %-12s %s\n",
               seq++, res->pid, res->uid, action_string(res->action), res->exe);
    }
    fw_objs_free(&procs);
}

static inline void nw_conn_clear(list *head)
{
    nw_conn *conn, *n;

    list_for_each_entry_safe(conn, n, head, list)  {
        list_delete(&conn->list);
        free(conn);
    }
}

static void conn_print(const nw_conn *conn)
{
    const conn_parm *p = &conn->conn.conn_parm;
    char protonum[20];
    const char *prot = "unknown";

    switch(p->src.l3num)  {
    case AF_INET:  {
        const unsigned char *ip_src = (const unsigned char *)&p->src.u3.ip;
        const unsigned char *ip_dst = (const unsigned char *)&p->dst.u3.ip;

        switch(p->dst.protonum)  {
        case IPPROTO_TCP:
            prot = "TCP";
            break;
        case IPPROTO_UDP:
            prot = "UDP";
            break;
        case IPPROTO_UDPLITE:
            prot = "UDPlite";
            break;
        case IPPROTO_ICMP:
            prot = "ICMP";
            break;
        default:
            sprintf(protonum, "[%u]", p->src.l3num);
            prot = protonum;
            break;
        }
        printf("[%-5llu] IPv4 %s   " IP_FMT "  " IP_FMT "  %u  %u\n",
               conn->seq, prot, IP_ARG(p->src.u3.ip), IP_ARG(p->dst.u3.ip),
               ntohs(p->src.u.tcp.port), ntohs(p->dst.u.tcp.port));
        break;
    }
    case AF_INET6:  {
        char ip6_addr[4][INET6_ADDRSTRLEN];

        switch(p->dst.protonum)  {
        case IPPROTO_TCP:
            prot = "TCP";
            break;
        case IPPROTO_UDP:
            prot = "UDP";
            break;
        case IPPROTO_UDPLITE:
            prot = "UDPlite";
            break;
        case IPPROTO_ICMP:
            prot = "ICMP";
            break;
        default:
            sprintf(protonum, "[%u]", p->src.l3num);
            prot = protonum;
            break;
        }
        printf("[%-5llu] IPv6 %s   %s  %s  %u  %u\n",
               conn->seq,  prot,
               inet_ntop(AF_INET6, p->src.u3.ip6, ip6_addr[0], INET6_ADDRSTRLEN) ? : "<INVALID>",
               inet_ntop(AF_INET6, p->dst.u3.ip6, ip6_addr[1], INET6_ADDRSTRLEN) ? : "<INVALID>",
               ntohs(p->src.u.tcp.port), ntohs(p->dst.u.tcp.port));
        break;
    }
    default:  {
        printf("[%-5llu] %u\n", conn->seq, p->src.l3num);
        break;
    }
    }
}

static inline void nw_conn_print(list *list)
{
    nw_conn *conn;

    list_for_each_entry(conn, list, list)  {
        conn_print(conn);
    }
}

static int cp_conn_cb(const msg_nw_connection *conn, void *ud)
{
    nw_conn_ctx *ctx = (nw_conn_ctx *)ud;
    nw_conn *nc;

    if((nc = new_instance(nw_conn)))  {
        nc->seq = ctx->seq++;
        memcpy(&nc->conn, conn, sizeof(*conn));
        list_append(&ctx->head, &nc->list);
        return 1;
    }
    printf("OOM alloc nw conn!\n");
    return 0;
}

static void list_conn(char *args[])
{
    nw_conn_ctx ctx;

    if(! args[0] || ! args[0][0])  {
        printf("Parameter \"conn\" requires arguments!\n");
        return;
    }

    list_init(&ctx.head);
    ctx.seq = 0;
    if(! strcasecmp(args[0], "proc"))  {
            char *endp;
            uid_t pid;

            if(! args[1] || ! args[1][0])  {
                printf("Parameter \"proc\" requires an argument, abort!\n");
                return;
            }
            pid = strtol(args[1], &endp, 0);
            if(*endp)  {
                printf("Not a valid PID \"%s\", abort!\n", args[1]);
                return;
            }

            desert_get_proc_conn(pid, cp_conn_cb, &ctx);
    }else if(! strcasecmp(args[0], "prog"))  {
        char *path, *endp;
        uid_t uid;

            if(! args[1] || ! args[1][0]
               || ! args[2] || ! args[2][0])  {
                printf("Parameter \"prog\" requires arguments, abort!\n");
                return;
            }

            path = args[1];
            uid = strtol(args[2], &endp, 0);
            if(*endp)  {
                printf("Not a valid UID \"%s\", abort!\n", args[1]);
                return;
            }

            desert_get_prog_conn(path, uid, cp_conn_cb, &ctx);
    }else if(! strcasecmp(args[0], "user"))  {
            char *endp;
            uid_t uid;

            if(! args[1] || ! args[1][0])  {
                printf("Parameter \"user\" requires an argument, abort!\n");
                return;
            }
            uid = strtol(args[1], &endp, 0);
            if(*endp)  {
                printf("Not a valid UID \"%s\", abort!\n", args[1]);
                return;
            }

            desert_get_user_conn(uid, cp_conn_cb, &ctx);
    }else  {
        printf("Unrecognized aregument \"%s\", abort!\n", args[0]);
        return;
    }

    if(list_empty(&ctx.head))  {
        printf("No records returned.\n");
        return;
    }

    nw_conn_clear(&conn_head);
    list_assign(&conn_head, &ctx.head);
    printf("SEQ     AF   PROTO SOURCE         DESTINATION  SPORT  DPORT\n");
    nw_conn_print(&conn_head);
}

static void cmd_list(char *args[], const command_desc *cd)
{
    char *cmd = args[0];

    if(! cmd || ! *cmd)  {
        printf("Verdict argument required!\n");
        return;
    }

    if(! strcasecmp(cmd, "verd"))  {
        list_verd();
    }else if(! strcasecmp(cmd, "prog"))  {
        list_prog(args + 1);
    }else if(! strcasecmp(cmd, "user"))  {
        list_user(args + 1);
    }else if(! strcasecmp(cmd, "proc"))  {
        list_proc(args + 1);
    }else if(! strcasecmp(cmd, "conn"))  {
        list_conn(args + 1);
    }else  {
        printf("Unrecognized command argument \"%s\", abort!\n", cmd);
    }
}

static void cmd_verd(char *args[], const command_desc *cd)
{
    verdict_record *r;
    char *cmd = args[0];
    size_t i;

    if(! cmd || ! *cmd)  {
        printf("Verdict argument required!\n");
        return;
    }

    /* TODO: more argument handling */
    for(i = 0; i < arraysize(verdict_cmd); i++)  {
        if(! strcasecmp(cmd, verdict_cmd[i].cmd))
            break;
    }
    if(i == arraysize(verdict_cmd))  {
        printf("Invalid verdict target!\n");
        return;
    }

    pthread_mutex_lock(&record_lock);
    if((r = record_list))
        record_list = r->next;
    pthread_mutex_unlock(&record_lock);

    if(r)  {
        if(desert_send_verdict(r->req[0].id, verdict_cmd[i].verd))  {
            ERROR("Fail to send verdict command for %llu!\n", r->req[0].id);
            exit(-1);
        }
        free(r);
    }
}

static void cmd_exit(char *args[], const command_desc *cd)
{
    exit(0);
}

static void cmd_help(char *args[], const command_desc *cd)
{
    const command_desc *c = cmd_tbl;
    char *cmd = args[0];

    if(! cmd || ! *cmd)  {
        printf("Available commands:\n");
        while(c->cmd)  {
            printf("    %-15s    %s\n", c->cmd, c->desc);
            c++;
        }
        return;
    }

    while(c->cmd)  {
        if(! strcasecmp(cmd, c->cmd))  {
            if(! c->get_help)  {
                printf("%s:\n\t%s\n", c->cmd, c->desc);
            }else  {
                printf("%s:\n%s\n", c->cmd, c->get_help(c->cmd));
            }
            return;
        }
        c++;
    }
    printf("Command \"%s\" unrecognized!\n", cmd);
}

static void get_logtype(char *args[])
{
    char *parm = args[0];
    int i, type = -1, err;
    msg_log_stat st;

    if(! parm || ! *parm)  {
        printf("Logtype argument required!\n");
        return;
    }

    if(strcasecmp(parm, "all"))  {
        for(i = 0; i < (int)arraysize(log_tbl); i++)  {
            if(! strcasecmp(log_tbl[i], parm))  {
                type = i;
                break;
            }
        }
        if(type == -1)  {
            printf("Unknown log type \"%s\"!\n", parm);
            return;
        }
    }

    if((err = desert_log_state(&st)))  {
        printf("Fail to get log state(%d)!\n", err);
        return;
    }

    if(type != -1)  {
        printf("%-10s : %s\n", log_tbl[type], st.ctl[type] ? "ENABLED" : "DISABLED");
        return;
    }

    for(i = 0; i < NUM_LOG; i++)
        printf("%-10s : %s\n", log_tbl[i], st.ctl[i] ? "ENABLED" : "DISABLED");
}

static void get_loglevel(char *args[])
{
    char *parm = args[0];
    int i, lvl = -1, err;
    msg_log_stat st;

    if(! parm || ! *parm)  {
        printf("Loglevel argument required!\n");
        return;
    }

    if(strcasecmp(parm, "all"))  {
        for(i = 0; i < (int)arraysize(level_tbl); i++)  {
            if(! strcasecmp(level_tbl[i], parm))  {
                lvl = i;
                break;
            }
        }
        if(lvl == -1)  {
            printf("Unknown log level \"%s\"!\n", parm);
            return;
        }
    }

    if((err = desert_log_state(&st)))  {
        printf("Fail to get log state(%d)!\n", err);
        return;
    }

    if(lvl != -1)  {
        printf("%-10s : %s\n", level_tbl[lvl], st.mask[lvl] ? "ENABLED" : "DISABLED");
        return;
    }

    for(i = 0; i < NUM_LVL; i++)
        printf("%-10s : %s\n", level_tbl[i], st.mask[i] ? "ENABLED" : "DISABLED");
}

static void get_action(char *args[])
{
    printf("TODO:\n");
}

static void get_throttle(char *args[])
{
    printf("TODO:\n");
}

static void get_counter(char *args[])
{
    printf("TODO:\n");
}

static void cmd_get(char *args[], const command_desc *cd)
{
    char *cmd = args[0];

    if(! cmd || ! *cmd)  {
        printf("Argument required!\n");
        return;
    }

    if(! strcasecmp(cmd, "logtype"))  {
        get_logtype(args + 1);
    }else if(! strcasecmp(cmd, "loglevel"))  {
        get_loglevel(args + 1);
    }else if(! strcasecmp(cmd, "action"))  {
        get_action(args + 1);
    }else if(! strcasecmp(cmd, "throttle"))  {
        get_throttle(args + 1);
    }else if(! strcasecmp(cmd, "counter"))  {
        get_counter(args + 1);
    }else if(! strcasecmp(cmd, "state"))  {
        char *st_str = "UNKNOWN";
        int st = desert_cactus_status();

        if(st == CACTUS_ACTIVE)
            st_str = "ACTIVE";
        else if(st == CACTUS_INACTIVE)
            st_str = "INACTIVE";

        printf("Cactus status: %s\n", st_str);
    }else if(! strcasecmp(cmd, "version"))  {
        const char *ver;
        int num;

        if((ver = desert_cactus_version(&num)))  {
            printf("%sVERSION(%X)\n", ver, num);
        }else  {
            printf("Unable to get version info!\n");
        }
    }else  {
        printf("Unrecognized argument \"%s\"!\n", cmd);
    }
}

static void set_front_end(char *args[])
{
    verdict_record *r;
    int st, err;

    if(! args[0] || ! args[0][0])  {
        printf("Argument required!\n");
        return;
    }

    if(! strcasecmp(args[0], "on"))  {
        st = 1;
    }else if(! strcasecmp(args[0], "off"))  {
        st = 0;
    }else  {
        printf("Invalid state spec \"%s\"!\n", args[0]);
        return;
    }

    pthread_mutex_lock(&record_lock);
    if(st && front_end)  {
        printf("Already in front-end mode.\n");
        goto out;
    }else if(! st && ! front_end)  {
        printf("Already out of front-end mode.\n");
        goto out;
    }else if(st)  {
        if((err = desert_register_fe(0, fe_cb, NULL)))  {
            printf("Fail to self register as front-end(%d)!", err);
            goto out;
        }else  {
            printf("Registered as front-end.\n");
            front_end = 1;
        }
    }else  {
        if((err = desert_unregister_fe(0)))  {
            printf("Fail to self unregister front-end(%d)!\n", err);
            goto out;
        }else  {
            printf("Unregistered front-end.\n");
            front_end = 0;
        }
    }

    if(record_list)  {
        printf("Clearing pending verdict(s):\n");
        __list_verd();
    }

    while(record_list)  {
        r = record_list;
        record_list = record_list->next;
        free(r);
    }
 out:
    pthread_mutex_unlock(&record_lock);
}

static void set_logtype(char *args[])
{
    int i, type = -1, st, err;

    if(! args[0] || ! args[0][0] || ! args[1] || ! args[1][0])  {
        printf("Logtype argument required!\n");
        return;
    }

    if(strcasecmp(args[0], "all"))  {
        for(i = 0; i < (int)arraysize(log_tbl); i++)  {
            if(! strcasecmp(log_tbl[i], args[0]))  {
                type = i;
                break;
            }
        }
        if(type == -1)  {
            printf("Unknown log type \"%s\"!\n", args[0]);
            return;
        }
    }

    if(! strcasecmp(args[1], "on"))  {
        st = 1;
    }else if(! strcasecmp(args[1], "off"))  {
        st = 0;
    }else  {
        printf("Invalid state spec \"%s\"!\n", args[1]);
        return;
    }

    if((err = desert_log_set_type_enabled(type, st)))  {
        printf("Fail to enable/disable log type(%d)!\n", err);
        return;
    }

    printf("Successfully %s log type \"%s.\n",
           st ? "enabled" : "disabled", args[0]);
}

static void set_loglevel(char *args[])
{
    int i, lvl = -1, st, err;

    if(! args[0] || ! args[0][0] || ! args[1] || ! args[1][0])  {
        printf("Loglevel argument required!\n");
        return;
    }

    if(strcasecmp(args[0], "all"))  {
        for(i = 0; i < (int)arraysize(level_tbl); i++)  {
            if(! strcasecmp(level_tbl[i], args[0]))  {
                lvl = i;
                break;
            }
        }
        if(lvl == -1)  {
            printf("Unknown log type \"%s\"!\n", args[0]);
            return;
        }
    }

    if(! strcasecmp(args[1], "on"))  {
        st = 1;
    }else if(! strcasecmp(args[1], "off"))  {
        st = 0;
    }else  {
        printf("Invalid state spec \"%s\"!\n", args[1]);
        return;
    }

    if((err = desert_log_set_level_enabled(lvl, st)))  {
        printf("Fail to enable/disable log level(%d)!\n", err);
        return;
    }

    printf("Successfully %s log level \"%s.\n",
           st ? "enabled" : "disabled", args[0]);
}

static void set_action(char *args[])
{
    printf("TODO:\n");
}

static void set_throttle(char *args[])
{
    printf("TODO:\n");
}

static void set_state(char *args[])
{
    char *parm = args[0];
    int st, err;

    if(! parm || ! *parm)  {
        printf("Argument required!\n");
        return;
    }

    if(! strcasecmp(parm, "on"))  {
        st = 1;
    }else if(! strcasecmp(parm, "off"))  {
        st = 0;
    }else  {
        printf("Invalid state spec \"%s\"!\n", parm);
        return;
    }

    if((err = desert_switch_cactus(st)))  {
        printf("Error switching cactus status(%d)!\n", err);
        return;
    }

    printf("Cactus status switched %s.\n", st ? "ACTIVE" : "INACTIVE");
}

static void cmd_set(char *args[], const command_desc *cd)
{
    char *cmd = args[0];

    if(! cmd || ! *cmd)  {
        printf("Argument required!\n");
        return;
    }

    if(! strcasecmp(cmd, "front-end"))  {
        set_front_end(args + 1);
    }else if(! strcasecmp(cmd, "logtype"))  {
        set_logtype(args + 1);
    }else if(! strcasecmp(cmd, "loglevel"))  {
        set_loglevel(args + 1);
    }else if(! strcasecmp(cmd, "action"))  {
        set_action(args + 1);
    }else if(! strcasecmp(cmd, "state"))  {
        set_state(args + 1);
    }else if(! strcasecmp(cmd, "throttle"))  {
        set_throttle(args + 1);
    }else  {
        printf("Unrecognized argument \"%s\"!\n", cmd);
    }
}

static void cmd_shutdown(char *args[], const command_desc *cd)
{
    desert_shutdown();
    printf("Done.\n");
    exit(0);
}

static void cmd_flush(char *args[], const command_desc *cd)
{
    desert_flush_logs();
    printf("Done.\n");
}

static void cmd_rule(char *args[], const command_desc *cd)
{
    printf("TODO:\n");
}

static char **tokenize(char ***toks, size_t *sz, char *str)
{
    char *p, **t, **_toks;
    int quoted = 0;
    int squoted = 0;
    int space;
    size_t cnt = 0;

    if(! *toks || ! *sz)  {
        *toks = (char **)malloc(sizeof(char *) * TOKS_MIN);
        *sz = TOKS_MIN;
    }
    if(! *toks)
        ERROR("OOM!");

    for(space = 1, t = *toks, p = str; *p; p++)  {
        if(! quoted && ! squoted && isspace(*p))  {
            *p = '\0';
            space = 1;
            continue;
        }
        if(! squoted && *p == '"')  {
            *p = '\0';
            quoted = !quoted;
            if(! quoted)
                memmove(p, p + 1, strlen(p + 1) + 1);
        }
        if(! quoted && *p == '\'')  {
            *p = '\0';
            squoted = ! squoted;
            if(! squoted)
                memmove(p, p + 1, strlen(p + 1) + 1);
        }

        if(space)  {
            space = 0;
            *t++ = p;
            cnt++;
            if(cnt + 1 == *sz)  {
                _toks = realloc(*toks, sizeof(char *) *(*sz + TOKS_MIN));
                if(_toks)  {
                    *sz += TOKS_MIN;
                    t = _toks + cnt;
                    *toks = _toks;
                }else  {
                    ERROR("OOM! extending toks array");
                }
            }
        }
    }
    if(quoted || squoted)
        return NULL;
    t = *toks;
    *(t + cnt) = NULL;
    return *toks;
}

static void dispatch_cmd(char **toks)
{
    const command_desc *cd = cmd_tbl;

    if(! *toks || ! **toks)
        return;

    while(cd->cmd)  {
        if(! strcmp(cd->cmd, toks[0]))  {
            cd->func(toks + 1, cd);
            return;
        }
        cd++;
    }
    printf("Unrecognized command, type help for help.\n");
}

static void parse_cmd(char *cmd)
{
    char **toks = NULL, *sharp, *p;
    size_t sz = 0;

    while(*cmd)  {
        for(p = cmd; *p; p++)  {
            if(*p == '#')  {
                *p++ = '\0';
                while(*p)  {
                    if(*p == '\n')  {
                        *p++ = '\0';
                        break;
                    }
                    p++;
                }
                break;
            }
            if(*p == '\n' || *p == ';')  {
                *p++ = '\0';
                break;
            }
        }

        if(! tokenize(&toks, &sz, cmd))  {
            printf("Malformated command & arguments!\n");
            return;
        }

        dispatch_cmd(toks);
        cmd = p;
    }
}

static void shell(void)
{
    char prompt[50], *cmd = NULL;
    int err;

    for(;;)  {
        pthread_mutex_lock(&record_lock);
        if(record_list)
            sprintf(prompt, "[verdict %llu] >", record_list->req[0].id);
        else if(front_end)
            strcpy(prompt, "[front end] >");
        else
            strcpy(prompt, "[lotus shell] >");
        pthread_mutex_unlock(&record_lock);

#ifndef ANDROID_CHANGES
        if(cmd)
            free(cmd);
        if(! (cmd = readline(prompt)))
            return;
        add_history(cmd);
#else
        char buf[1024];

        printf("%s", prompt);
        if(! (cmd = fgets(buf, sizeof(buf), stdin)))
            return;
#endif
        parse_cmd(cmd);
    }
}

int main(int argc, char *argv[])
{
    int cmd = CMD_NONE;
    int c, idx, log = -1, lvl = -1, stat = 0, ver_num;
    char *arg = NULL, *command = NULL;
    int err = -1;
    size_t i;
    const char *ver;
    static struct option opts[] = {
        {"load", 1, NULL, 'l'},
        {"flush", 0, NULL, 'f'},
        {"dump", 1, NULL, 'd'},
        {"status", 0, NULL, 'u'},
        {"state", 1, NULL, 's'},
        {"log", 1, NULL, 'g'},
        {"cactus", 0, NULL, 'c'},
        {"level", 1, NULL, 'L'},
        {"help", 0, NULL, 'h'},
        {"shutdown", 0, NULL, 'S'},
        {"shell", 0, NULL, 't'},
        {"command", 1, NULL, 'C'},
        {"version", 0, NULL, 'v'},
        {"test", 1, NULL, 'T'},
        {NULL, 0, NULL, 0}
    };

    for(;;)  {
        c = getopt_long(argc, argv, "l:fd:us:g:cL:hStC:vT:", opts, &idx);
        if(-1 == c)
            break;

        switch(c)  {
        case 'l':
            SET_CMD(LOAD);
            SET_ARG();
            break;
        case 'f':
            SET_CMD(FLUSH_LOGS);
            break;
        case 'd':
            SET_CMD(DUMP);
            SET_ARG();
            break;
        case 'u':
            SET_CMD(STATUS);
            break;
        case 's':
            if(! optarg)
                ERROR("state argument required.");
            if(! strcasecmp(optarg, "on"))
                stat = 1;
            else if(! strcasecmp(optarg, "off"))
                stat = 0;
            else
                ERROR("Invalid argument.");
            break;
        case 'g':
            SET_CMD(LOG_CONTROL);
            if(! optarg)
                ERROR("Log name required.");
            for(i = 0; i < arraysize(log_tbl); i++)  {
                if(! strcasecmp(log_tbl[i], optarg))  {
                    log = i;
                    break;
                }
            }
            if(! strcasecmp("all", optarg))
                break;
            if(log == -1)
                ERROR("Invalid log name.");
            break;
        case 'c':
            SET_CMD(CACTUS_CONTROL);
            break;
        case 'L':
            SET_CMD(LEVEL_CONTROL);
            if(! optarg)
                ERROR("Level name required.");
            for(i = 0; i < arraysize(level_tbl); i++)  {
                if(! strcasecmp(level_tbl[i], optarg))  {
                    lvl = i;
                    break;
                }
            }
            if(! strcasecmp("all", optarg))
                break;
            if(lvl == -1)
                ERROR("Invalid log level name.");
            break;
        case 'h':
            help(argv[0]);
            return 0;
        case 'S':
            SET_CMD(SHUTDOWN);
            break;
        case 't':
            SET_CMD(SHELL);
            break;
        case 'C':
            SET_CMD(COMMAND);
            if(! optarg)
                ERROR("Argument required.");
            command = optarg;
            break;
        case 'v':
            SET_CMD(VERSION);
            break;
        case 'T':
            SET_CMD(TEST);
            SET_ARG();
            break;
        default:
            fprintf(stderr, "Invalid argment.\n");
            help(argv[0]);
            return -1;
        }
    }

    if(cmd != CMD_NONE)  {
        if((err = desert_init(banner, on_connect_cb, NULL)))
            ERROR_RET(err, "Fail initializing desert.");
        if((err = desert_connect(NULL, NULL, 0)))
            ERROR_RET(err, "Fail to init connection to Lavender.");
        switch(cmd)  {
        case CMD_LOAD:
            err = desert_load_rules(arg);
            break;
        case CMD_FLUSH_LOGS:
            err = desert_flush_logs();
            break;
        case CMD_DUMP:
            err = desert_dump_rules(arg);
            break;
        case CMD_STATUS:
            stat = desert_cactus_status();
            if(stat == CACTUS_ACTIVE || stat == CACTUS_INACTIVE)  {
                err = 0;
                printf("Cactus status: %s\n", stat ? "ACTIVE" : "INACTIVE");
            }
            break;
        case CMD_LOG_CONTROL:
            err = desert_log_set_type_enabled(log, stat);
            break;
        case CMD_LEVEL_CONTROL:
            err = desert_log_set_level_enabled(lvl, stat);
            break;
        case CMD_CACTUS_CONTROL:
            err = desert_switch_cactus(stat);
            break;
        case CMD_SHUTDOWN:
            err = desert_shutdown();
            break;
        case CMD_SHELL:
            shell();
            err = 0;
            break;
        case CMD_COMMAND:
            parse_cmd(command);
            err = 0;
            break;
        case CMD_VERSION:
            ver = desert_cactus_version(&ver_num);
            if(ver)  {
                printf("%sVERSION(%X)\n", ver, ver_num);
                err = 0;
            }
            break;
        case CMD_TEST:  {
            char buf[1024];

            err = desert_make_test(arg, buf, sizeof(buf));
            if(! err)
                printf("TEST RES:\"%s\"\n", buf);
            break;
        }
        default:
            ERROR_RET(err, "Invalid command:%d.", cmd);
            break;
        }

        if(err)
            ERROR_RET(err, "Command execution failed:%d.", err);
        return err;
    }

    ERROR_RET(err, "Nothing to do.");
    return err;
}

