/*
 * cactus_be.c
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

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>

#include "msg_base.h"
#include "msg.h"
#include "ipclite.h"
#include "rpclite.h"
#include "rule.h"
#include "core.h"
#include "fd_lookup.h"
#include "fw_table.h"
#include "sig_handle.h"
#include "cactus_be.h"
#include "cactus_log.h"

static const int cactus_version = 0x00000130;
static const char cactus_banner[] = "Cactus Runtime - Version " VERSION "\n"
    "Copyright (C) 2012 Crs Chin<crs.chin@gmail.com>\n";

#define list_for_each_ipclite_msg_safe(iter,n,head)                     \
    for(iter = list_entry((head)->l_nxt,typeof(*iter),ctl),             \
            n = list_entry(((list *)&iter->ctl)->l_nxt, typeof(*iter), ctl); \
        (list *)&iter->ctl != (head);                                   \
        iter = n, n = list_entry(((list *)&iter->ctl)->l_nxt,typeof(*iter),ctl))

#define MAX_PENDING 20

static pthread_mutex_t __lock = PTHREAD_MUTEX_INITIALIZER;
static int __initialized = 0;
static int __registered = 0;
static unsigned int __peer = 0;
static int __seq = 0;
static list __pending = LIST_HEAD_INIT(__pending);
static int __pending_cnt = 0;

typedef struct _for_each_ctx for_each_ctx;

struct _for_each_ctx{
    rpclite_response rsp;
    void *ud;
};

static inline void be_lock()
{
    pthread_mutex_lock(&__lock);
}

static inline void be_unlock()
{
    pthread_mutex_unlock(&__lock);
}

static inline void __flush_pending(void)
{
    ipclite_msg *msg, *n;

    list_for_each_ipclite_msg_safe(msg, n, &__pending)  {
        list_delete((list *)&msg->ctl);
        msg->hdr.peer = __peer;
        msg_send(msg, 0, 1);
    }
    __pending_cnt = 0;
}

static int __for_each_verd_cb(fw_obj *fobj, void *ud)
{
    /* stop if any failure */
    return ! cactus_be_send_verdict(fobj);
}

static int __for_each_conn_cb(__u16 zone, const conn_tuple *src, void *ud)
{
    for_each_ctx *ctx = (for_each_ctx *)ud;
    msg_nw_connection conn;
    conn_parm *parm = &conn.conn_parm;

    conn.zone = zone;
    parm->src.u3 = src->src.u3;
    parm->src.u = src->src.u;
    parm->src.l3num = src->src.l3num;
    parm->dst.u3 = src->dst.u3;
    parm->dst.u.all = src->dst.u.all;
    parm->dst.protonum = src->dst.protonum;
    return ! ctx->rsp(&conn, sizeof(conn), RPCLITE_RSP_MORE, ctx->ud);
}

static int __for_each_prog_cb(const char *path, uid_t uid, int action, void *ud)
{
    for_each_ctx *ctx = (for_each_ctx *)ud;
    char rsp[sizeof(msg_prog_res) + strlen(path) + 1];
    msg_prog_res *res = (msg_prog_res *)&rsp;

    res->uid = uid;
	res->action = action;
    strcpy(res->path, path);
    return ! ctx->rsp(res, sizeof(rsp), RPCLITE_RSP_MORE, ctx->ud);
}

static int __for_each_user_cb(const char *name, uid_t uid, void *ud)
{
    for_each_ctx *ctx = (for_each_ctx *)ud;
	char rsp[sizeof(msg_user_res) + strlen(name) + 1];
	msg_user_res *res = (msg_user_res *)&rsp;

	res->uid = uid;
	strcpy(res->name, name);
    return ! ctx->rsp(res, sizeof(rsp), RPCLITE_RSP_MORE, ctx->ud);
}

static int __for_each_proc_cb(const char *path, pid_t pid, uid_t uid, int action, void *ud)
{
    for_each_ctx *ctx = (for_each_ctx *)ud;
	char rsp[sizeof(msg_proc_res) + strlen(path) + 1];
	msg_proc_res *res = (msg_proc_res *)&rsp;

	res->pid = pid;
	res->uid = uid;
	res->action = action;
	strcpy(res->exe, path);
    return ! ctx->rsp(res, sizeof(rsp), RPCLITE_RSP_MORE, ctx->ud);
}

static inline void tuple_assign(conn_tuple *tuple, const conn_parm *parm)
{
    tuple->src.u3 = parm->src.u3;
    tuple->src.u = parm->src.u;
    tuple->src.l3num = parm->src.l3num;
    tuple->dst.u3 = parm->dst.u3;
    tuple->dst.u.all = parm->dst.u.all;
    tuple->dst.protonum = parm->dst.protonum;
}

static int svc_handler(int req, const char *blob, size_t sz, rpclite_response rsp, void *rsp_ud, void *ud)
{
    int err = CACTUS_ERR_OK;

    LOG_DEBUG("received cactus rpc req:%d", req);
    switch(req)  {
    case CACTUS_REQ_REGISTER_FE:  {
        msg_fe_register *reg = (msg_fe_register *)blob;
        ipclite_peer info;

        if(! blob || sz != sizeof(*reg))
            return CACTUS_ERR_BAD_PARM;

        be_lock();
        if(__registered)  {
            err = CACTUS_ERR_ALREADY_REGISTERED;
            break;
        }
        __peer = reg->peer;
        if(msg_peer_info(__peer, &info))  {
            err = CACTUS_ERR_NO_SUCH_PEER;
            break;
        }
        __registered = 1;
        LOG_INFO("front-end peer %u registered", __peer);

        if(__pending_cnt > 0)  {
            LOG_INFO("flush pending verdict request on front-end registering");
            __flush_pending();
        }
        break;
    }
    case CACTUS_REQ_UNREGISTER_FE:  {
        msg_fe_unregister *unreg = (msg_fe_unregister *)blob;

        if(! blob || sz != sizeof(*unreg))
            return CACTUS_ERR_BAD_PARM;

        be_lock();
        if(! __registered || __peer != unreg->peer)  {
            err = CACTUS_ERR_NOT_REGISTERED;
            break;
        }
        __peer = 0;
        __registered = 0;
        LOG_INFO("front-end peer %u deregistered", unreg->peer);
        break;
    }
    case CACTUS_REQ_RULE_LOAD:  {
        const char *path = (const char *)blob;

        if(! blob || sz < 2 || path[sz - 1])
            return CACTUS_ERR_BAD_PARM;

        be_lock();
        LOG_INFO("install fw rules from \"%s\"", path);
        if(rule_install(path))  {
            LOG_WARN("failed to install rules from \"%s\"", path);
            err = CACTUS_ERR_GENERIC;
        }
        break;
    }
    case CACTUS_REQ_RULE_DUMP:  {
        const char *path = (const char *)blob;
        struct stat st;

        if(! blob || sz < 2 || path[sz - 1])
            return CACTUS_ERR_BAD_PARM;

        be_lock();
        if(! stat(path, &st))  {
            LOG_ERROR("not dumping rules to existing file:\"%s\"", path);
            err = CACTUS_ERR_GENERIC;
            break;
        }
        LOG_INFO("dump fw rules into \"%s\"", path);
        if(rule_dump(path))  {
            LOG_WARN("fail to dump fw rules into \"%s\"", path);
            err = CACTUS_ERR_GENERIC;
        }
        break;
    }
    case CACTUS_REQ_CORE_ACTIVATE:  {
        be_lock();
        LOG_INFO("activate the cactus engine");
        if(core_activate())  {
            LOG_WARN("failed to activate the cactus engine");
            err = CACTUS_ERR_GENERIC;
        }
        break;
    }
    case CACTUS_REQ_CORE_DEACTIVATE:  {
        be_lock();
        LOG_INFO("deactivate the cactue engine");
        core_deactivate();
        break;
    }
    case CACTUS_REQ_CORE_STATUS:  {
        msg_core_status st;

        be_lock();
        st.status = core_status();
        if(rsp(&st, sizeof(st), 0, rsp_ud))
            err = CACTUS_ERR_GENERIC;
        break;
    }
    case CACTUS_REQ_CORE_VERSION:  {
        char _ver[sizeof(msg_core_version) + sizeof(cactus_banner)];
        msg_core_version *ver = (msg_core_version *)&_ver;

        ver->version = cactus_version;
        ver->len = sizeof(cactus_banner);
        strcpy(ver->banner, cactus_banner);

        be_lock();
        if(rsp(&_ver, sizeof(_ver), 0, rsp_ud))
            err = CACTUS_ERR_GENERIC;
        break;
    }
    case CACTUS_REQ_LOG_FLUSH:  {
        be_lock();
        LOG_INFO("flushing cactus logs");
        cactus_log_flush();
        break;
    }
    case CACTUS_REQ_LOG_CONTROL:  {
        msg_log_ctl *ctl = (msg_log_ctl *)blob;
        int i;

        if(! blob || sz != sizeof(*ctl))
            return CACTUS_ERR_BAD_PARM;
        be_lock();
        LOG_INFO("log control update:%d %d %d %d",
                 ctl->ctl[LOG_MAIN], ctl->ctl[LOG_RTNL],
                 ctl->ctl[LOG_UEVENT], ctl->ctl[LOG_CONNTRACK]);
        LOG_INFO("log level update:%d %d %d %d %d %d",
                 ctl->mask[LOG_DEBUG], ctl->mask[LOG_INFO],
                 ctl->mask[LOG_WARN], ctl->mask[LOG_EMERG],
                 ctl->mask[LOG_ERROR], ctl->mask[LOG_FATAL]);
        for(i = 0; i < NUM_LOG; i++)
            cactus_log_set_ctl(i, ctl->ctl[i]);
        memcpy(log_mask, &ctl->mask, sizeof(log_mask));
        break;
    }
    case CACTUS_REQ_LOG_STATE:  {
        msg_log_stat log_st;

        be_lock();
        memcpy(&log_st.ctl, log_ctl, sizeof(log_ctl));
        memcpy(&log_st.mask, log_mask, sizeof(log_mask));
        if(rsp(&log_st, sizeof(log_st), 0, rsp_ud))
            err = CACTUS_ERR_GENERIC;
        break;
    }
    case CACTUS_REQ_CORE_EXIT:  {
        be_lock();
        /* answer the client and quit */
        LOG_INFO("Cactus Runtime requested exiting ...");
        rsp(NULL, 0, RPCLITE_RSP_SYN, rsp_ud);
        core_exit(0);
        LOG_FATAL("Should never print!");
        break;
    }
    /* Cactus misc configurations */
    case CACTUS_REQ_COUNTER_STATUS:  {
        msg_counter_status *st = (msg_counter_status *)blob;

        if(! blob || sz != sizeof(*st))
            return CACTUS_ERR_BAD_PARM;
        be_lock();
        if(st->cmd == CMD_SET)  {
            if(fw_table_set_counter_enable(st->status) < 0)
                err = CACTUS_ERR_GENERIC;
        }else if(st->cmd == CMD_QUERY)  {
            msg_counter_status stat = {
                .cmd = CMD_QUERY,
            };

            if(fw_table_get_counter_enable(&stat.status))  {
                err = CACTUS_ERR_GENERIC;
                break;
            }
            if(rsp(&stat, sizeof(stat), 0, rsp_ud))
                err = CACTUS_ERR_GENERIC;
        }else  {
            err = CACTUS_ERR_BAD_PARM;
        }
        break;
    }
    case CACTUS_REQ_FW_TABLE_STATE:  {
        fw_stat fwst;
        msg_fw_table_state st;

        be_lock();
        fw_table_get_stat(&fwst);
        st.connections = fwst.conns;
        st.programs = fwst.progs;
        st.processes = fwst.procs;
        st.users = fwst.users;
        if(rsp(&st, sizeof(st), 0, rsp_ud))
            err = CACTUS_ERR_GENERIC;
        break;
    }
    /* cactus will resent all pending verdicts */
    case CACTUS_REQ_REFRESH_VERDICT:  {
        be_lock();
        fw_table_verd_refresh();
        fw_table_for_each_verd(__for_each_verd_cb, NULL);
        break;
    }
    /* immediate control on specific network connection */
    case CACTUS_REQ_THROTTLE_CONNECTION:  {
        msg_throttle_req *req = (msg_throttle_req *)blob;

        if(! blob || sz < sizeof(*req))
            return CACTUS_ERR_BAD_PARM;

        be_lock();
        if(req->cmd == CMD_SET)  {
            switch(req->type)  {
            case THROTTLE_CONN:  {
                conn_tuple tuple;

                tuple_assign(&tuple, &req->conn_parm);
                if(fw_table_set_throttle_conn(req->zone, &tuple, req->enabled))
                    err = CACTUS_ERR_GENERIC;
                break;
            }
            case THROTTLE_PROC:  {
                if(fw_table_set_throttle_proc(req->pid, req->enabled))
                    err = CACTUS_ERR_GENERIC;
                break;
            }
            case THROTTLE_PROG:  {
                const char *path = req->path;
                size_t len = sz - sizeof(*req);

                /* at least a char and '\0' */
                if(len < 2 || path[len - 1] != '\0')  {
                    err = CACTUS_ERR_BAD_PARM;
                    break;
                }
                if(fw_table_set_throttle_prog(path, req->uid, req->enabled))
                    err = CACTUS_ERR_GENERIC;
                break;
            }
            case THROTTLE_USER:  {
                if(fw_table_set_throttle_user(req->uid, req->enabled))
                    err = CACTUS_ERR_GENERIC;
                break;
            }
            default:
                err = CACTUS_ERR_BAD_PARM;
                break;
            }
        }else if(req->cmd == CMD_QUERY)  {
            msg_throttle_res res = {
                .type = req->type,
            };

            switch(req->type)  {
            case THROTTLE_CONN:  {
                conn_tuple tuple;

                tuple_assign(&tuple, &req->conn_parm);
                res.enabled = fw_table_get_throttle_conn(req->zone, &tuple);
                break;
            }
            case THROTTLE_PROC:  {
                res.enabled = fw_table_get_throttle_proc(req->pid);
                break;
            }
            case THROTTLE_PROG:  {
                const char *path = req->path;
                size_t len = sz - sizeof(*req);

                /* at least a char and '\0' */
                if(len < 2 || path[len - 1] != '\0')  {
                    err = CACTUS_ERR_BAD_PARM;
                    break;
                }
                res.enabled = fw_table_get_throttle_prog(path, req->uid);
                break;
            }
            case THROTTLE_USER:  {
                res.enabled = fw_table_get_throttle_user(req->uid);
                break;
            }
            default:
                err = CACTUS_ERR_BAD_PARM;
                break;
            }
            if(err == CACTUS_ERR_OK)  {
                if(rsp(&res, sizeof(res), 0, rsp_ud))
                    err = CACTUS_ERR_GENERIC;
            }
        }else  {
            err = CACTUS_ERR_BAD_PARM;
        }
        break;
    }
    case CACTUS_REQ_QUERY_NW_CONNECTION:  {
        msg_query_nw_req *req = (msg_query_nw_req *)blob;
        for_each_ctx ctx = {
            .rsp = rsp,
            .ud = rsp_ud,
        };

        if(! blob || sz < sizeof(*req))
            return CACTUS_ERR_BAD_PARM;

        be_lock();
        switch(req->type)  {
        case TYPE_PROC:  {
            fw_table_for_each_conn_of_proc(req->pid, __for_each_conn_cb, &ctx);
            break;
        }
        case TYPE_PROG:  {
            const char *path = req->path;
            size_t len = sz - sizeof(*req);

            /* at least a char and '\0' */
            if(len < 2 || path[len - 1] != '\0')  {
                err = CACTUS_ERR_BAD_PARM;
                break;
            }

            fw_table_for_each_conn_of_prog(path, req->uid, __for_each_conn_cb, &ctx);
            break;
        }
        case TYPE_USER:  {
            fw_table_for_each_conn_of_user(req->uid, __for_each_conn_cb, &ctx);
            break;
        }
        default:
            err = CACTUS_ERR_BAD_PARM;
            break;
        }
        break;
    }
    case CACTUS_REQ_QUERY_NW_COUNTER:  {
        msg_query_nw_req *req = (msg_query_nw_req *)blob;
        fw_counter fcounter;
        msg_nw_counter counter;

        if(! blob || sz < sizeof(*req))
            return CACTUS_ERR_BAD_PARM;
        be_lock();
        switch(req->type)  {
        case TYPE_CONN:  {
            conn_tuple tuple;

            tuple_assign(&tuple, &req->conn_parm);
            if(fw_table_get_conn_counter(req->zone, &tuple, &fcounter))
                err = CACTUS_ERR_GENERIC;
            break;
        }
        case TYPE_PROC:  {
            if(fw_table_get_proc_counter(req->pid, &fcounter))
                err = CACTUS_ERR_GENERIC;
            break;
        }
        case TYPE_PROG:  {
            const char *path = req->path;
            size_t len = sz - sizeof(*req);

            /* at least a char and '\0' */
            if(len < 2 || path[len - 1] != '\0')  {
                err = CACTUS_ERR_BAD_PARM;
                break;
            }
            if(fw_table_get_prog_counter(path, req->uid, &fcounter))
                err = CACTUS_ERR_GENERIC;
            break;
        }
        case TYPE_USER:  {
            if(fw_table_get_user_counter(req->uid, &fcounter))
                err = CACTUS_ERR_GENERIC;
            break;
        }
        case TYPE_GLOBAL:  {
            fw_table_get_global_counter(&fcounter);
            break;
        }
        default:
            err = CACTUS_ERR_BAD_PARM;
            break;
        }
        if(err == CACTUS_ERR_OK)  {
            counter.orig_pkts = fcounter.orig_pkts;
            counter.orig_bytes = fcounter.orig_bytes;
            counter.rep_pkts = fcounter.rep_pkts;
            counter.rep_bytes = fcounter.rep_bytes;
            if(rsp(&counter, sizeof(counter), 0, rsp_ud))
                err = CACTUS_ERR_GENERIC;
        }
        break;
    }
    case CACTUS_REQ_QUERY_FW_OBJECT:  {
        msg_query_fw_req *req = (msg_query_fw_req *)blob;
        for_each_ctx ctx = {
            .rsp = rsp,
            .ud = rsp_ud,
        };

        if(! blob || sz < sizeof(*req))
            return CACTUS_ERR_BAD_PARM;
        be_lock();
        switch(req->type)  {
        case TYPE_PROG:  {
            fw_table_for_each_prog(req->active_only ? ITER_F_ACTIVE : 0,
                                   __for_each_prog_cb, &ctx);
            break;
        }
        case TYPE_USER:  {
            fw_table_for_each_user(req->active_only ? ITER_F_ACTIVE : 0,
                                   __for_each_user_cb, &ctx);
            break;
        }
        case TYPE_PROC:  {
            switch(req->by_which)  {
            case BY_NONE:  {
                fw_table_for_each_proc(__for_each_proc_cb, &ctx);
                break;
            }
            case BY_PROG:  {
                const char *path = req->path;
                size_t len = sz - sizeof(*req);

                /* at least a char and '\0' */
                if(len < 2 || path[len - 1] != '\0')  {
                    err = CACTUS_ERR_BAD_PARM;
                    break;
                }

                fw_table_for_each_proc_of_prog(path, __for_each_proc_cb, &ctx);
                break;
            }
            case BY_USER:  {
                fw_table_for_each_proc_of_user(req->uid, __for_each_proc_cb, &ctx);
                break;
            }
            default:
                err = CACTUS_ERR_BAD_PARM;
                break;
            }
            break;
        }
        default:
            err = CACTUS_ERR_BAD_PARM;
            break;
        }
        break;
    }
    case CACTUS_REQ_CFG_FW_RULE:  {
        /* TODO: */
        break;
    }
    case CACTUS_REQ_MAKE_TEST:  {
        char *parm = (char *)blob;
        char *res = "Cactus Test Interface";

        be_lock();
        if(parm)  {
            if(! strcmp(parm, "SIGSEGV"))
                *(volatile int *)0 = 0;
        }
        if(rsp(res, strlen(res) + 1, 0, rsp_ud))
            err = CACTUS_ERR_GENERIC;
        break;
    }
    default:  {
        LOG_ERROR("unrecognized RPC request:%d", req);
        return CACTUS_ERR_UNKNOWN_REQ;
    }
    }
    be_unlock();
    return err;
}

static const char *nf_verd_tbl[] = {
    "NONE",
    "QUERY",
    "ALLOW_ONCE",
    "ALLOW_ALWAYS",
    "DENY_ONCE",
    "DENY_ALWAYS",
    "KILL_ONCE",
    "KILL_ALWAYS",
};

static int be_handler(ipclite_msg *msg, void *ud)
{
    LOG_DEBUG("received ipc msg:%d", msg->hdr.msg);
    switch(msg->hdr.msg)  {
    case CACTUS_VERDICT_RESULT:  {
        msg_verdict_res *verd = MSG_PAYLOAD(msg_verdict_res, msg);

        if(verd->verdict >= 0 && verd->verdict < (int)arraysize(nf_verd_tbl))  {
            fw_table_verd(verd->id, verd->verdict);
            LOG_INFO("received verdict %s to %" PRIu64, nf_verd_tbl[verd->verdict], verd->id);
            break;
        }
        LOG_WARN("invalid verdict %u to %" PRIu64 " received, ignore", verd->verdict, verd->id);
        break;
    }
    case IPCLITE_MSG_CLS:  {
        be_lock();
        if(__registered && __peer == msg->hdr.peer)  {
            __registered = 0;
            __peer = 0;
            LOG_INFO("front-end peer %u disconnected", msg->hdr.peer);
        }
        be_unlock();
        break;
    }
    default:  {
        LOG_ERROR("unrecognized IPC message:%d", msg->hdr.msg);
        break;
    }
    }

    free(msg);
    return 1;
}

static int sig_term(const struct signalfd_siginfo *info, sig_handler *h)
{
    LOG_INFO("SIGTERM received, cleanup and exit ...");
    core_exit(0);
    return 1;
}

static rpclite_svc cactus_svc = {
    .svc_name = CACTUS_SVC_NAME,
    .handler = svc_handler,
    .ud = NULL,
};

static msg_handler handler_desc = {
    .base = CACTUS_VERDICT_BASE,
    .range = RANGE_CACTUS_VERDICT,
    .h = be_handler,
    .ud = NULL,
};

/* we exit on SIGTERM, ignore the others */
static sig_handler sig_desc[] = {
    {.num = SIGTERM, .cb = sig_term,},
};

int cactus_be_init(void)
{
    if(! __initialized)  {
        if(rpclite_svc_register(&cactus_svc))  {
            LOG_ERROR("fail to register Cactus back-end svc");
            return -1;
        }
        if(msg_register_handler(&handler_desc))  {
            LOG_ERROR("fail to register Cactus msg handler");
            return -1;
        }
        if(sig_register_handler(sig_desc, arraysize(sig_desc)) != arraysize(sig_desc))  {
            LOG_ERROR("unable to register all sig handlers");
            sig_unregister_handler(sig_desc, arraysize(sig_desc));
            return -1;
        }
        __initialized = 1;
    }
    return 0;
}

static msg_fd_owner *fill_mfo(msg_fd_owner *mfo, fd_owner *fo)
{
    mfo->euid = fo->euid;
    mfo->egid = fo->egid;
    mfo->pid = fo->pid;
    mfo->ppid = fo->ppid;
    mfo->tgid = fo->tgid;
    mfo->tracerpid = fo->tracerpid;
    mfo->sid = fo->sid;
    strcpy(mfo->exe, fo->exe);
    return (msg_fd_owner *)((char *)mfo + sizeof(*mfo) + strlen(fo->exe) + 1);
}

int cactus_be_send_verdict(fw_obj *fobj)
{
    size_t sz = sizeof(msg_verdict_req);
    ipclite_msg *msg;
    msg_verdict_req *req;
    msg_fd_owner *mfo;
    fd_owner *fo;
    list *head;
    int err;

    head = fobj->fos;
    if(list_empty(head))  {
        LOG_WARN("no object for which to send verdict");
        return -1;
    }
    list_for_each_entry(fo,head,list)  {
        sz += sizeof(msg_fd_owner) + strlen(fo->exe) + 1;
    }

    if(! (msg = ipclite_msg_alloc(__peer, ++__seq, CACTUS_VERDICT_REQUEST, sz)))
        return -1;

    req = MSG_PAYLOAD(msg_verdict_req, msg);
    req->id = fobj->id;
    req->ts = fobj->ts;
    mfo = &req->fos[0];

    head = fobj->fos;
    req->fo_count = 0;
    list_for_each_entry(fo,head,list)  {
        mfo = fill_mfo(mfo, fo);
        req->fo_count++;
    }

    be_lock();
    if(! __registered || ! __peer)  {
        if(__pending_cnt < MAX_PENDING)  {
            list_append(&__pending, (list *)&msg->ctl);
            __pending_cnt++;
            LOG_INFO("no front-end registered, "
                     "pending verdict request, cnt %d", __pending_cnt);
        }else  {
            ipclite_msg_free(msg);
            LOG_WARN("pending verdicts exceeds the limit %d, discarding!", MAX_PENDING);
        }
        be_unlock();
        return 0;
    }
    be_unlock();

    err = msg_send(msg, 0, 1);
    return ((err < 0) ? err : 0);
}

int cactus_be_send_info(int type, int len, char *info)
{
    ipclite_msg *msg;
    msg_runtime_info *mvi;
    size_t sz = sizeof(*mvi);
    int err;

    if(! __registered || ! __peer)
        /* just dump it and return success if no front-end
           available */
        return 0;

    if(len < 0)
        len = strlen(info) + 1;
    sz += len;

    if(! (msg = ipclite_msg_alloc(__peer, ++__seq, CACTUS_RUNTIME_INFO, sz)))
        return -1;

    mvi = MSG_PAYLOAD(msg_runtime_info, msg);
    mvi->type = type;
    mvi->time = time(NULL);
    mvi->len = len;
    memcpy(&mvi->info, info, len);

    /* msg server wil dump it if peer just disconnected */
    err = msg_send(msg, 0, 1);
    return ((err < 0) ? err : 0);
}

int cactus_be_send_printf(int type, const char *fmt, ...)
{
    va_list ap;
    char *s;
    int len, err = -1;

    if(! __registered || ! __peer)
        return 0;

    va_start(ap, fmt);
    if((len = vasprintf(&s, fmt, ap)) > 0)  {
        err = cactus_be_send_info(type, len + 1, s);
        free(s);
    }
    va_end(ap);
    return err;
}

