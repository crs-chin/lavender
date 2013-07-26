/*
 * fw_table.c
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

/* re-implement fw_rule.c for better efficiency and control */

#include <assert.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <linux/types.h>
#include <pthread.h>

#include "util.h"
#include "branch.h"
#include "jhash.h"
#include "msg_base.h"
#include "timer.h"
#include "nfct.h"
#include "sock_stat.h"
#include "fd_lookup.h"
#include "fw_table.h"
#include "async_work.h"
#include "cactus_be.h"
#include "cactus_log.h"

#ifndef FW_TABLE_HASH_SIZE
 #define FW_TABLE_HASH_SIZE
 #define INIT_CONN_HASH_SIZE (1024 * 2)
 #define INIT_PROG_HASH_SIZE (1024)
 #define INIT_IDENT_HASH_SIZE (1024)
 #define INIT_PROC_HASH_SIZE (1024 * 2)
 #define INIT_USER_HASH_SIZE (1024)
#endif

#define VERDICT_DEBOUNCE_TIMER 45

#define FW_TABLE_GC_TIMER 30000

/* all connections with this mark will be nuked */
#define BLACK_HOLE ((__u32)-1)

typedef struct _fw_table fw_table;

struct _fw_table{
    /* const once initialized */
    size_t conn_sz;
    size_t prog_sz;
    size_t ident_sz;
    size_t proc_sz;
    size_t user_sz;
    /* protect all below, FIXME: imporve here */
    pthread_mutex_t lock;
    hlist_head *conn_table;
    hlist_head *prog_table;
    hlist_head *ident_table;
    hlist_head *proc_table;
    hlist_head *user_table;
    fw_counter counter;
    list verd;
    list procs;
    fw_stat stat;
    __u64 rid;
    /* read only */
    fw_cb cbs;
    nfct_t *ct;
    /* jhash */
    __u32 initval;
    int gc_timeout;
    timer gc_timer;
};

#define FW_MSG_KILL 1

typedef struct _fw_msg fw_msg;
typedef struct _fw_msg_kill fw_msg_kill;

struct _fw_msg{
    int type;
};

struct _fw_msg_kill{
    fw_msg msg;
    list fos;
};

static int initialized = 0;;
static pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER;
static __u64 id_pool = 0;
static __u32 mark_pool = 0;
static async_handler msg_work = {
    .name = "fw_table_work",
};

static const int gc_timeout[] = {
    15 * 1000,
    30 * 1000,
    30 * 1000,
    1 * 60 * 1000,
    1 * 60 * 1000,
    2 * 60 * 1000,
    4 * 60 * 1000,
    8 * 60 * 1000,
    16 * 60 * 1000,
    32 * 60 * 1000,
};

static fw_table init_table;


static const char *verd_string[] = {
    "accepted",             /* accepted, but still check the following
                              kernel rules */
    "reinjected",               /* accepted, reinject into NW stack */
    "queued for the verdict",            /* query front-end */
    "denied",               /* packet dropped */
    "killed",               /* terminate process */
};

static int gc(void *ud);

static inline void table_lock(void)
{
    pthread_mutex_lock(&init_table.lock);
}

static inline void table_unlock(void)
{
    pthread_mutex_unlock(&init_table.lock);
}

static inline hlist_head *hash_alloc(size_t *sz, size_t min)
{
    hlist_head *h;

    /* should be anyway cachealigned, or proportional to physical mem
       size? */
    if((h = (hlist_head *)malloc(sizeof(hlist_head) * min)))  {
        memset(h, 0, sizeof(hlist_head) * min);
        *sz = min;
    }
    return h;
}

static void async_msg_handler(async_handler *handler, void *msg)
{
    fw_msg *fm = (fw_msg *)msg;

    switch(fm->type)  {
    case FW_MSG_KILL:  {
        fw_msg_kill *fmk = (fw_msg_kill *)fm;
        fd_owner *fo, *n;
        int delay = 0;

        /* TODO: clear fw_proc after terminated */
        for(delay = 0; ! list_empty(&fmk->fos); delay += 100000)  {
            list_for_each_entry_safe(fo, n, &fmk->fos, list)  {
                if(! delay)  {
                    LOG_INFO("terminating \"%s\" PID:%u", fo->exe, fo->pid);
                    /* should always be able to send a signal, so if failed,
                       process should be gone already */
                    if(! kill(fo->pid, SIGTERM))
                        continue;
                }else if(! kill(fo->pid, 0))  {
                    if(delay < 1500000)
                        continue;
                    /* wait 1.5 sec at most */
                    LOG_WARN("force killing \"%s\" PID:%u", fo->exe, fo->pid);
                    kill(fo->pid, SIGKILL);
                    CACTUS_BE_MSG("Force killed \"%s\", UID:%u, PID:%u", fo->exe, fo->euid, fo->pid);
                }else  {
                    CACTUS_BE_MSG("Terminated \"%s\", UID:%u, PID:%u", fo->exe, fo->euid, fo->pid);
                }
                list_delete(&fo->list);
                if(fo->grps)
                    free(fo->grps);
                free(fo);
            }
            usleep(delay);
        }
        break;
    }
    default:
        LOG_ERROR("unrecognized fw msg:%d", fm->type);
        break;
    }
}

static inline void fos_term(list *fos)
{
    async_handler_msg *am = new_instance_ex(async_handler_msg, sizeof(fw_msg_kill));
    fw_msg_kill *fmk;

    if(am)  {
        am->id = msg_work.id;
        fmk = (fw_msg_kill *)am->msg;
        fmk->msg.type = FW_MSG_KILL;
        list_assign(&fmk->fos, fos);
        async_post(am);
    }
}

static int __do_init(fw_table *t, const fw_cb *cb, nfct_t *ct)
{
    memset(t, 0, sizeof(*t));
    pthread_mutex_init(&t->lock, NULL);
    list_init(&t->verd);
    list_init(&t->procs);
    memcpy(&t->cbs, cb, sizeof(*cb));
    t->ct = ct;

    srandom(time(NULL));
    t->initval = (__u32)random();

    if(! (t->conn_table = hash_alloc(&t->conn_sz, INIT_CONN_HASH_SIZE)))  {
        LOG_EMERG("fail to alloc conntrack hash table");
        goto err_cleanup;
    }
    LOG_INFO("conntrack hash size %u", t->conn_sz);

    if(! (t->prog_table = hash_alloc(&t->prog_sz, INIT_PROG_HASH_SIZE)))  {
        LOG_EMERG("fail to alloc prog hash table");
        goto err_cleanup;
    }
    LOG_INFO("prog hash size %u", t->prog_sz);

    if(! (t->ident_table = hash_alloc(&t->ident_sz, INIT_IDENT_HASH_SIZE)))  {
        LOG_EMERG("fail to alloc ident hash table");
        goto err_cleanup;
    }
    LOG_INFO("ident hash size %u", t->ident_sz);

    if(! (t->proc_table = hash_alloc(&t->proc_sz, INIT_PROC_HASH_SIZE)))  {
        LOG_EMERG("fail to alloc proc hash table");
        goto err_cleanup;
    }
    LOG_INFO("proc hash size %u", t->proc_sz);

    if(! (t->user_table = hash_alloc(&t->user_sz, INIT_USER_HASH_SIZE)))  {
        LOG_EMERG("fail to alloc user hash table");
        goto err_cleanup;
    }
    LOG_INFO("user hash size %u", t->user_sz);

    timer_init(&t->gc_timer, NULL, gc, NULL);
    if(timer_register_src(&t->gc_timer))  {
        LOG_EMERG("unable to register fw table gc timer");
        goto err_cleanup;
    }

    msg_work.handler = async_msg_handler;
    if(async_register_handler(&msg_work))  {
        LOG_EMERG("unable to regiser fw table async work");
        goto err_cleanup;
    }

    return 0;

 err_cleanup:
    free_if(t->conn_table);
    free_if(t->prog_table);
    free_if(t->ident_table);
    free_if(t->proc_table);
    free_if(t->user_table);
    timer_unregister_src(&t->gc_timer);
    return -1;
}

/**
 * @flags: unused currently
 */
int fw_table_init(const fw_cb *cb, nfct_t *ct, int flags)
{
    assert(! initialized);

    if(cb && cb->verdict_req && ct && ! __do_init(&init_table, cb, ct))  {
        initialized = 1;
        return 0;
    }
    return -1;
}

/* same hash as the kernel's impl. */
static inline __u32 hash_conn(const conn_tuple *tuple, __u16 zone, size_t sz, __u32 initval)
{
    __u32 n = (sizeof(tuple->src) + sizeof(tuple->dst.u3)) / sizeof(__u32);
    __u32 h = jhash2((__u32 *)tuple, n,
                     zone ^ initval ^ (((__u16)tuple->dst.u.all << 16) | tuple->dst.protonum));

    return ((__u64)h * sz) >> 32;
}

static inline int nf_addr_eq(const union nf_inet_addr *a, const union nf_inet_addr *b)
{
    return (a->all[0] == b->all[0]
            && a->all[1] == b->all[1]
            && a->all[2] == b->all[2]
            && a->all[3] == b->all[3]);
}

static inline int tuple_equal(const conn_tuple *a, const conn_tuple *b)
{
    return (nf_addr_eq(&a->src.u3, &b->src.u3)
            && a->src.u.all == b->src.u.all
            && a->src.l3num == b->src.l3num
            && nf_addr_eq(&a->dst.u3, &b->dst.u3)
            && a->dst.u.all == b->dst.u.all
            && a->dst.protonum == b->dst.protonum);
}

static fw_conn *__conn_lookup(const conn_tuple *tuple, __u16 zone)
{
    __u32 hash = hash_conn(tuple, zone, init_table.conn_sz, init_table.initval);
    hlist_head *h = &init_table.conn_table[hash];
    fw_conn *iter;
    hlist *pos;

    hlist_for_each_entry(iter, pos, h, node)  {
        if(tuple_equal(&iter->src, tuple) && iter->zone == zone)
            return iter;
    }
    return NULL;
}

/**
 * return non-zero if already exist
 */
static int __conn_insert(fw_conn *conn)
{
    __u32 hash = hash_conn(&conn->src, conn->zone, init_table.conn_sz, init_table.initval);
    hlist_head *h = &init_table.conn_table[hash];
    fw_conn *iter;
    hlist *pos;

    hlist_for_each_entry(iter, pos, h, node)  {
        if(tuple_equal(&iter->src, &conn->src) && iter->zone == conn->zone)
            return -1;
    }
    hlist_prepend(h, &conn->node);
    init_table.stat.conns++;
    return 0;
}

static inline void __conn_unhash(fw_conn *conn)
{
    hlist_delete(&conn->node);
    init_table.stat.conns++;
}

static inline __u32 hash_string(const char *path, size_t sz)
{
    return (__u32)(djb2_hash((const unsigned char *)path) % sz);
}

static fw_prog *__prog_lookup(const char *path)
{
    __u32 hash = hash_string(path, init_table.prog_sz);
    hlist_head *h = &init_table.prog_table[hash];
    fw_prog *iter;
    hlist *pos;

    hlist_for_each_entry(iter, pos, h, node)  {
        if(! strcmp(path, iter->path))
            return iter;
    }
    return NULL;
}

static int __prog_insert(fw_prog *prog)
{
    __u32 hash = hash_string(prog->path, init_table.prog_sz);
    hlist_head *h = &init_table.prog_table[hash];
    fw_prog *iter;
    hlist *pos;

    hlist_for_each_entry(iter, pos, h, node)  {
        if(! strcmp(iter->path, prog->path))
            return -1;
    }
    hlist_prepend(h, &prog->node);
    init_table.stat.progs++;
    return 0;
}

static inline void __prog_unhash(fw_prog *prog)
{
    hlist_delete(&prog->node);
    init_table.stat.progs--;
}

static inline __u32 hash_ident(uid_t uid, const char *str, size_t sz)
{
    return (__u32)((djb2_hash((const unsigned char *)str) + uid) % sz);
}

static fw_ident *__ident_lookup(uid_t uid, const char *path)
{
    __u32 hash = hash_ident(uid, path, init_table.ident_sz);
    hlist_head *h = &init_table.ident_table[hash];
    fw_ident *iter;
    hlist *pos;

    hlist_for_each_entry(iter, pos, h, node)  {
        if(iter->uid == uid && ! strcmp(path, iter->prog->path))
            return iter;
    }
    return NULL;
}

static int __ident_insert(fw_ident *ident)
{
    uid_t uid = ident->uid;
    const char *path = ident->prog->path;
    __u32 hash = hash_ident(uid, path, init_table.ident_sz);
    hlist_head *h = &init_table.ident_table[hash];
    fw_ident *iter;
    hlist *pos;

    hlist_for_each_entry(iter, pos, h, node)  {
        if(iter->uid == uid && ! strcmp(iter->prog->path, path))
            return -1;
    }
    hlist_prepend(h, &ident->node);
    init_table.stat.idents++;
    return 0;
}

static inline void __ident_unhash(fw_ident *ident)
{
    hlist_delete(&ident->node);
    init_table.stat.idents--;
}

static inline __u32 hash_number(unsigned long num, size_t sz)
{
    return (__u32)(num % sz);
}

static fw_proc *__proc_lookup(pid_t pid)
{
    __u32 hash = hash_number(pid, init_table.proc_sz);
    hlist_head *h = &init_table.proc_table[hash];
    fw_proc *iter;
    hlist *pos;

    hlist_for_each_entry(iter, pos, h, node)  {
        if(iter->pid == pid)
            return iter;
    }
    return NULL;
}

static int __proc_insert(fw_proc *proc)
{
    __u32 hash = hash_number(proc->pid, init_table.proc_sz);
    hlist_head *h = &init_table.proc_table[hash];
    fw_proc *iter;
    hlist *pos;

    hlist_for_each_entry(iter, pos, h, node)  {
        if(iter->pid == proc->pid)
            return -1;
    }
    hlist_prepend(h, &proc->node);
    list_append(&init_table.procs, &proc->list);
    init_table.stat.procs++;
    return 0;
}

static inline void __proc_unhash(fw_proc *proc)
{
    hlist_delete(&proc->node);
    list_delete(&proc->list);
    init_table.stat.procs--;
}

static fw_user *__user_lookup(uid_t uid)
{
    __u32 hash = hash_number(uid, init_table.user_sz);
    hlist_head *h = &init_table.user_table[hash];
    fw_user *iter;
    hlist *pos;

    hlist_for_each_entry(iter, pos, h, node)  {
        if(iter->uid == uid)
            return iter;
    }
    return NULL;
}

static int __user_insert(fw_user *user)
{
    __u32 hash = hash_number(user->uid, init_table.user_sz);
    hlist_head *h = &init_table.user_table[hash];
    fw_user *iter;
    hlist *pos;

    hlist_for_each_entry(iter, pos, h, node)  {
        if(iter->uid == user->uid)
            return -1;
    }
    hlist_prepend(h, &user->node);
    init_table.stat.users++;
    return 0;
}

static inline void __user_unhash(fw_user *user)
{
    hlist_delete(&user->node);
    init_table.stat.users--;
}

static inline int validate_action(int action)
{
    int tg = action & TARGET_MASK;
    int vd = action >> VERDICT_SHIFT;

    if(tg < FW_ACCEPT
       || tg > FW_KILL
       || (tg == FW_VERDICT
           && (vd <= VERDICT_NONE
               || vd >= NUM_VERDICT)))  {
        LOG_ERROR("invalid action code:0x%X", action);
        return -1;
    }
    return 0;
}

static inline void fw_verd_init(fw_verd *v, int action, int obj)
{
    list_init(&v->list);
    v->flags = (obj & VERDICT_OBJ_MASK) << VERDICT_OBJ_SHIFT;
    v->action = action;
    v->grp = NULL;
}

static inline void fw_counter_init(fw_counter *c)
{
    c->orig_pkts = 0;
    c->orig_bytes = 0;
    c->rep_pkts = 0;
    c->rep_bytes = 0;
}

static inline int fw_verd_obj(fw_verd *v)
{
    return ((v->flags >> VERDICT_OBJ_SHIFT) & VERDICT_OBJ_MASK);
}

static fw_conn *conn_alloc(const conn_tuple *src, __u16 zone)
{
    fw_conn *fc;

    if((fc = new_instance(fw_conn)))  {
        hlist_init(&fc->node);
        fc->zone = zone;
        memcpy(&fc->src, src, sizeof(*src));
        pthread_mutex_lock(&pool_lock);
        do{
            fc->mark = ++mark_pool;
        }while(fc->mark == BLACK_HOLE || ! fc->mark);
        pthread_mutex_unlock(&pool_lock);
        /* below filled up later */
        fc->ino = 0;
        leaf_init(&fc->proc_entry);
        fw_counter_init(&fc->counter);
    }
    return fc;
}

static inline void conn_free(fw_conn *con)
{
    free(con);
}

static inline void __conn_release(fw_conn *con)
{
    __conn_unhash(con);
    leaf_free(&con->proc_entry);
}

static void prog_init(fw_prog *p, const char *path, const char *csum, size_t sz)
{
    hlist_init(&p->node);
    memset(p->csum, 0, sizeof(p->csum));
    if(csum)
        memcpy(p->csum, csum, sizeof(p->csum));
    p->sz = sz;
    list_init(&p->ident);
    strcpy(p->path, path);
}

static inline fw_prog *prog_new(const char *path, const char *csum, size_t sz)
{
    fw_prog *prog;

    if((prog = new_instance_ex(fw_prog, strlen(path) + 1)))
        prog_init(prog, path, csum, sz);
    return prog;
}

static inline fw_prog *prog_new_from_fo(fd_owner *fo)
{
    /* TODO: calculate csum and size */
    return prog_new(fo->exe, NULL, 0);
}

/* should already have all refernce released */
static inline void prog_free(fw_prog *fp)
{
    free(fp);
}

static fw_ident *ident_new(uid_t uid, fw_prog *prog)
{
    fw_ident *ident;

    if((ident = new_instance(fw_ident)))  {
        hlist_init(&ident->node);
        list_init(&ident->prog_entry);
        list_init(&ident->procs);
        fw_verd_init(&ident->action,
                     FW_VERDICT | (VERDICT_QUERY << VERDICT_SHIFT),
                     VERDICT_OBJ_IDENT);
        ident->uid = uid;
        fw_counter_init(&ident->counter);
        ident->prog = prog;
        if(prog)
            list_append(&prog->ident, &ident->prog_entry);
    }
    return ident;
}

static inline void __ident_release(fw_ident *fi)
{
    __ident_unhash(fi);
    list_delete(&fi->prog_entry);
}

static inline void ident_free(fw_ident *ident)
{
    free(ident);
}

static fw_proc *proc_new(fd_owner *fo)
{
    fw_proc *p;
	int sz = strlen(fo->exe) + 1;

    if((p = new_instance_ex(fw_proc, sz)))  {
        hlist_init(&p->node);
        fw_verd_init(&p->action,
                     FW_VERDICT | (VERDICT_QUERY << VERDICT_SHIFT),
                     VERDICT_OBJ_PROC);
        p->pid = fo->pid;
        p->ppid = fo->ppid;
        p->sid = fo->sid;
        p->uid = fo->euid;
        p->gid = fo->egid;
        p->magic = fo->ino;
		strcpy(p->exe, fo->exe);
        /* below filled on insertion */
        p->ident = NULL;
        list_init(&p->list);
        list_init(&p->ident_entry);
        list_init(&p->user_entry);
        branch_init(&p->conns);
        fw_counter_init(&p->counter);
    }
    return p;
}

static inline void __proc_release(fw_proc *proc)
{
    __proc_unhash(proc);
    branch_free(&proc->conns);
}

static inline void proc_free(fw_proc *proc)
{
    free(proc);
}

static fw_user *user_new(const char *name, uid_t uid, size_t ngrps, const gid_t *grps)
{
    fw_user *user;
    char *buf = NULL;
    size_t payload = 1;

    if(! name)  {
        struct passwd pwd, *res = NULL;
        int buf_sz = sysconf(_SC_GETPW_R_SIZE_MAX);

        if(buf_sz < 0)
            buf_sz = 16384;     /* should be more than enough */
        if((buf = (char *)malloc(buf_sz)))  {
            if(! getpwuid_r(uid, &pwd, buf, buf_sz, &res) && res)
                name = pwd.pw_name;
        }
    }
    if(! name)
        name = "";

    payload += strlen(name) + ngrps * sizeof(gid_t) + 1;

    if((user = new_instance_ex(fw_user, payload)))  {
        hlist_init(&user->node);
        user->uid = uid;
        strcpy(user->name, name);
        user->ngrps = ngrps;
        if(ngrps)  {
            user->gid = (gid_t *)((char *)user + sizeof(fw_user) + strlen(name) + 1);
            memcpy(user->gid, grps, ngrps * sizeof(gid_t));
        }else  {
            user->gid = NULL;
        }
        user->flags = 0;
        list_init(&user->procs);
        fw_counter_init(&user->counter);
    }
    free_if(buf);
    return user;
}

static inline void user_free(fw_user *fu)
{
    free(fu);
}

static fw_verd_grp *__get_verd_grp(__u64 id)
{
    fw_verd_grp *grp;
    int err;

    if(! id)  {
        if(! (grp = new_instance(fw_verd_grp)))
            return NULL;
        list_init(&grp->list);
        list_init(&grp->verds);
        list_init(&grp->fos);
        /* should never fail this */
        err = clock_gettime(CLOCK_MONOTONIC, &grp->ts);
        assert(! err);
        grp->ts.tv_sec += VERDICT_DEBOUNCE_TIMER;
        pthread_mutex_lock(&pool_lock);
        grp->id = ++id_pool;
        pthread_mutex_unlock(&pool_lock);
        return grp;
    }

    list_for_each_entry(grp, &init_table.verd, list)  {
        if(grp->id == id)
            return grp;
    }
    return NULL;
}

static inline void verd_grp_release(fw_verd_grp *grp)
{
    list_delete(&grp->list);
    fd_owners_free(&grp->fos);
    free(grp);
}

static inline void ___verd_grp_add(fw_verd_grp *grp, fw_verd *verd)
{
    verd->flags |= VERDICT_F_VERD;
    verd->grp = grp;
    list_append(&grp->verds, &verd->list);
}

static void __verd_grp_add(fw_verd_grp **vgrp, fw_verd *verd, __u64 *rid)
{
    fw_verd_grp *grp;
    struct timespec ts;

    if(verd->flags & VERDICT_F_VERD)  {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        grp = verd->grp;
        *rid = grp->id;
        if(ts_cmp(&ts, &grp->ts) <= 0)
            return;
        /* TODO: should notify anything here? */
        verd->grp = NULL;
        verd->flags &= ~VERDICT_F_VERD;
        list_delete(&verd->list);
        if(list_empty(&grp->verds))  {
            list_delete(&grp->list);
            free(grp);
        }
        /* debounce timer expired, resend verdict */
    }

    if(! *vgrp && ! (*vgrp = __get_verd_grp(0)))  {
        LOG_EMERG("unable to alloc verd grp");
        return;
    }

    ___verd_grp_add(*vgrp, verd);
}

static inline int prog_verify(fw_prog *fp)
{
    /* TODO: verify if executable was replaced, and invalidate the
     * prog rule if affirmative, but this could be time consuming,
     * implement if really necessary.
     */
    return 0;
}

static inline int do_verdict(fw_verd *v)
{
    /* drop all throttled */
    if(v->flags & VERDICT_F_THROTTLE)
        return FW_DROP;
    return v->action & TARGET_MASK;
}

static int __ident_judge(fw_ident *fi, fd_owner *fo)
{
    int tg, verd;

    if(prog_verify(fi->prog))  {
        /* TODO: update prog verification info */
        return FW_VERDICT;
    }

    tg = do_verdict(&fi->action);
    if(tg != FW_VERDICT)
        return tg;

    verd = (fi->action.action >> VERDICT_SHIFT);
    switch(verd)  {
    case VERDICT_NONE:
        LOGINFO("VERDICT_NONE, silent drop rule judged");
        tg = FW_DROP;
        break;
    case VERDICT_QUERY:
        tg = FW_VERDICT;
        break;
    case VERDICT_ALLOW_ONCE: /* fall back into VERDICT_QUERY after once */
        tg = FW_ACCEPT;
        fi->action.action = ((fi->action.action & TARGET_MASK) | (VERDICT_QUERY << VERDICT_SHIFT));
        break;
    case VERDICT_ALLOW_ALWAYS:
        tg = FW_ACCEPT;
        fi->action.action = (VERDICT_QUERY << VERDICT_SHIFT) | FW_ACCEPT;
        break;
    case VERDICT_DENY_ONCE: /* fall back into VERDICT_QUERY after once */
        tg = FW_DROP;
        fi->action.action = ((fi->action.action & TARGET_MASK) | (VERDICT_QUERY << VERDICT_SHIFT));
        break;
    case VERDICT_DENY_ALWAYS:
        tg = FW_DROP;
        fi->action.action = (VERDICT_QUERY << VERDICT_SHIFT) | FW_DROP;
        break;
    case VERDICT_KILL_ONCE: /* fall back into VERDICT_QUERY after once */
        tg = FW_KILL;
        fi->action.action = ((fi->action.action & TARGET_MASK) | (VERDICT_QUERY << VERDICT_SHIFT));
        break;
    case VERDICT_KILL_ALWAYS:
        tg = FW_KILL;
        fi->action.action = (VERDICT_QUERY << VERDICT_SHIFT) | FW_KILL;
        break;
    default:
        LOG_EMERG("fw table unexpected verdict:%u", verd);
        tg = FW_DROP;
        break;
    }

    return tg;
}

/* reset gc timeout value */
static inline void __sched_gc(void)
{
    init_table.gc_timeout = 0;
    __timer_sched(&init_table.gc_timer, 0, gc_timeout[init_table.gc_timeout]);
}

static int ___walk_table(fd_owner *fo, fw_verd_grp **vgrp, __u64 *vid)
{
    fw_proc *proc;
    fw_prog *fp;
    fw_ident *fi = NULL;
    fw_user *user;
    fw_verd *fv;
    int err, verd;

    if((proc = __proc_lookup(fo->pid)))  {
        verd = do_verdict(&proc->action);
        if(verd != FW_VERDICT)
            return verd;
    }else if((proc = proc_new(fo)))  {
        if(! (fi = __ident_lookup(fo->euid, fo->exe)))  {
            if(! (fp = __prog_lookup(fo->exe)))  {
                fp = prog_new_from_fo(fo);
                if(! fp || __prog_insert(fp))  {
                    if(fp)
                        prog_free(fp);
                    proc_free(proc);
                    LOG_EMERG("unable to initiate or insert new fw prog:%u,%s", fo->euid, fo->exe);
                    return FW_DROP;
                }
            }

            fi = ident_new(fo->euid, fp);
            if(! fi || __ident_insert(fi))  {
                if(fi)
                    ident_free(fi);
                proc_free(proc);
                LOG_EMERG("unable to initiate or insert new fw ident:%u", fo->euid);
                return FW_DROP;
            }
        }

        if(! (user = __user_lookup(fo->euid)))  {
            user = user_new(NULL, fo->euid, fo->ngrps, fo->grps);
            if(! user || __user_insert(user))  {
                if(user)
                    user_free(user);
                proc_free(proc);
                LOG_EMERG("unable to initiate or insert new fw user:%u", fo->euid);
                return FW_DROP;
            }
        }

        proc->ident = fi;
        list_append(&fi->procs, &proc->ident_entry);
        list_append(&user->procs, &proc->user_entry);
        __proc_insert(proc);
        __sched_gc();
    }else  {
        LOG_EMERG("unable to alloc new fw proc");
        return FW_DROP;
    }

    /* should never fail to lookup now */
    if(! fi && ! (fi = __ident_lookup(fo->euid, fo->exe)))  {
        LOG_EMERG("unable to lookup fw ident");
        return FW_DROP;
    }
    verd = __ident_judge(fi, fo);

    if(verd == FW_VERDICT)  {
        __verd_grp_add(vgrp, &proc->action, vid);
        __verd_grp_add(vgrp, &fi->action, vid);
    }else  {
        fv = &proc->action;
        fv->action = verd;
        if(fv->flags & VERDICT_F_VERD)  {
            list_delete(&fv->list);
            if(list_empty(&fv->grp->verds))  {
                list_delete(&fv->grp->list);
                free(fv->grp);
            }
            fv->grp = NULL;
            fv->flags &= ~VERDICT_F_VERD;
        }
    }

    return verd;
}

/**
 * @vid is the id of the last verd grp if available, otherwise
 * undefiend
 */
static int __walk_table(list *h, fw_verd_grp **vgrp, __u64 *vid)
{
    fd_owner *fo;
    int verd = FW_ACCEPT, v;

    assert(! list_empty(h));
    list_for_each_entry(fo, h, list)  {
        v = ___walk_table(fo, vgrp, vid);
        /* one kill, all got killed if connection shared */
        if(v > verd)  {
            verd = v;
            if(verd == FW_KILL)
                break;
        }
    }
    assert(verd >= FW_ACCEPT && verd <= FW_KILL);
    return verd;
}

/**
 * @vid: verdict request id to return if @fos is going to be pending
 * for front-end's final decision, otherwise undefined, verdict
 * returned on return.
 */
int fw_table_walk(list *fos, void *ctx, __u64 *vid)
{
    fw_verd_grp *vgrp = NULL;
    fd_owner *fo;
    fw_obj fobj;
    int verd;
    __u64 id;

    table_lock();
    verd = __walk_table(fos, &vgrp, &id);
    if(verd == FW_VERDICT)  {
        if(vgrp)  {
            vgrp->ctx = ctx;
            list_assign(&vgrp->fos, fos);
            list_append(&init_table.verd, &vgrp->list);
            if(init_table.cbs.verdict_req)  {
                fobj.id = vgrp->id;
                fobj.ts = vgrp->ts;
                fobj.fos = &vgrp->fos;
                init_table.cbs.verdict_req(&fobj, init_table.cbs.req_ud);
            }
            if(vid)
                *vid = vgrp->id;
        }else if(vid)  {
            *vid = id;
        }
    }else if(verd == FW_KILL)  {
        list_for_each_entry(fo, fos, list)  {
            CACTUS_BE_MSG("Terminating \"%s\", UID:%u, PID:%u", fo->exe, fo->euid, fo->pid);
        }
        fos_term(fos);
    }else  {
        /* only tell front-end denied actions */
        if(verd != FW_ACCEPT)  {
            list_for_each_entry(fo, fos, list)  {
                CACTUS_BE_MSG_RATELIMIT_PID(fo->pid, "Process %u(%s:%u) %s to access network",
                                            fo->pid, fo->exe, fo->euid, verd_string[verd]);
            }
        }
        fd_owners_free(fos);
    }
    table_unlock();
    return verd;
}

static int __verdict_grp(fw_verd_grp *grp, int verd)
{
    fw_verd *fv, *n;
    int action_proc;
    int action;

    switch(verd)  {
    case VERDICT_QUERY:
        action = FW_VERDICT | (VERDICT_QUERY << VERDICT_SHIFT);
        action_proc = FW_VERDICT | (VERDICT_QUERY << VERDICT_SHIFT);
        break;
    case VERDICT_ALLOW_ONCE:
        action = FW_VERDICT | (VERDICT_QUERY << VERDICT_SHIFT);
        action_proc = FW_ACCEPT;
        break;
    case VERDICT_DENY_ONCE:
        action = FW_VERDICT | (VERDICT_QUERY << VERDICT_SHIFT);
        action_proc = FW_DROP;
        break;
    case VERDICT_KILL_ONCE:
        action = FW_VERDICT | (VERDICT_QUERY << VERDICT_SHIFT);
        action_proc = FW_KILL;
        break;
    case VERDICT_ALLOW_ALWAYS:
        action = FW_ACCEPT;
        action_proc = FW_ACCEPT;
        break;
    case VERDICT_DENY_ALWAYS:
        action = FW_DROP;
        action_proc = FW_DROP;
        break;
    case VERDICT_KILL_ALWAYS:
        action = FW_KILL;
        action_proc = FW_KILL;
        break;
    default:
        LOG_ERROR("invalid verdict %d", verd);
        return -1;
    }
    list_for_each_entry_safe(fv, n, &grp->verds, list)  {
        list_delete(&fv->list);
        fv->flags &= ~VERDICT_F_VERD;
        switch(fw_verd_obj(fv))  {
        case VERDICT_OBJ_IDENT:
            fv->action = action;
            break;
        case VERDICT_OBJ_PROC:
            fv->action = action_proc;
            break;
        default:
            LOG_EMERG("unexpected fw verd object:%u", fw_verd_obj(fv));
            break;
        }
    }
    if(action_proc == FW_KILL)
        fos_term(&grp->fos);
    verd_grp_release(grp);
    return 0;
}

static inline int __do_verdict(__u64 rid, int verd, void **ctx)
{
    fw_verd_grp *grp;

    assert(verd > VERDICT_NONE && verd < NUM_VERDICT);
    list_for_each_entry(grp, &init_table.verd, list)  {
        if(grp->id == rid)  {
            *ctx = grp->ctx;
            return __verdict_grp(grp, verd);
        }
    }
    return -1;
}

int fw_table_verd(__u64 rid, int verdict)
{
    int err;
    void *ctx;

    table_lock();
    err = __do_verdict(rid, verdict, &ctx);
    table_unlock();
    if(! err && init_table.cbs.verdict_res)
        init_table.cbs.verdict_res(rid, ctx, verdict, init_table.cbs.res_ud);
    return err;
}

static int __alter_proc_action(fw_proc *proc, int action)
{
    /* TODO: */
    return -1;
}

int fw_table_set_proc_action(pid_t pid, int action)
{
    fw_proc *proc;
    int err = -ENOENT;

    if(validate_action(action))
        return -1;

    table_lock();
    if((proc = __proc_lookup(pid)))  {
        err = 0;
        if(proc->action.action != action)
            err = __alter_proc_action(proc, action);
    }
    table_unlock();
    return err;
}

int fw_table_get_proc_action(pid_t pid, int *action)
{
    /* TODO: */
    return -1;
}

int fw_table_set_prog_action(const char *prog, uid_t uid, int action)
{
    /* TODO: */
    return -1;
}

int fw_table_get_prog_action(const char *prog, uid_t uid, int *action)
{
    /* TODO: */
    return -1;
}

static int insert_rule(const char *path, const char *csum,
                       size_t sz, uid_t uid, int action,
                       const fw_counter *c)
{
    fw_prog *fp;
    fw_ident *fi;
    int err = -1;

    if(validate_action(action))
        return -1;

    table_lock();
    if(! (fp = __prog_lookup(path)))  {
        fp = prog_new(path, csum, sz);
        if(! fp || __prog_insert(fp))  {
            if(fp)
                prog_free(fp);
            table_unlock();
            LOG_EMERG("fail to initiate or insert new fw prog:%s", path);
            return -1;
        }
    }
    if(! (fi = __ident_lookup(uid, path)))  {
        fi = ident_new(uid, fp);
        if(! fi || __ident_insert(fi))  {
            if(fi)
                ident_free(fi);
            table_unlock();
            LOG_EMERG("fail to initiate or insert new fw ident:%u,%s", uid, path);
            return -1;
        }
    }

    fi->counter = *c;
    fi->action.action = action;
    table_unlock();
    return 0;
}

static int insert_user(const char *name, uid_t uid, const fw_counter *c)
{
    fw_user *fu = user_new(name, uid, 0, NULL);
    int err = -1;

    if(fu)  {
        fu->counter = *c;
        table_lock();
        err = __user_insert(fu);
        table_unlock();
        if(err)
            user_free(fu);
    }
    return err;
}

int fw_table_insert(const fw_conf *c)
{
    switch(c->type)  {
    case FW_CONF_RULE:
        return insert_rule(c->rule.path, c->rule.csum, c->rule.sz,
                           c->rule.uid, c->rule.action,
                           &c->rule.counter);
    case FW_CONF_USER:
        return insert_user(c->user.name, c->user.uid, &c->user.counter);
    case FW_CONF_COUNTER:
        table_lock();
        init_table.counter = c->counter;
        table_unlock();
        return 0;
    default:
        LOG_WARN("unrecognized fw conf type %u, ignored", c->type);
        break;
    }
    return -1;
}

static inline void __fw_verd_release(fw_verd *v)
{
    fw_verd_grp *grp;

    if(v->flags & VERDICT_F_VERD)  {
        list_delete(&v->list);
        grp = v->grp;
        if(list_empty(&grp->verds))
            verd_grp_release(grp);
    }
}

static int delete_rule(const char *prog, uid_t uid)
{
    fw_prog *fp;
    fw_ident *fi;
    int err = 0;

    table_lock();
    if((fi = __ident_lookup(uid, prog)))  {
        if(! list_empty(&fi->procs))  {
            LOG_WARN("unable to delete referenced rule \"%s\" uid %u, stop", prog, uid);
            err = -1;
        }else  {
            LOG_INFO("removing fw ident \"%s\", uid %u, action 0x%X",
                     prog, uid, fi->action.action);
            fp = fi->prog;
            __ident_release(fi);
            ident_free(fi);
            if(list_empty(&fp->ident))  {
                __prog_unhash(fp);
                prog_free(fp);
            }
        }
    }else  if((fp = __prog_lookup(prog)) && list_empty(&fp->ident))  {
        __prog_unhash(fp);
        prog_free(fp);
    }
    table_lock();
    return err;
}

static int delete_user(uid_t uid)
{
    fw_user *fu;
    int err = 0;

    table_lock();
    if((fu = __user_lookup(uid)))  {
        if(! list_empty(&fu->procs))  {
            LOG_WARN("unable to delete referenced user %u fw rule, stop", uid);
            err = -1;
        }else  {
            LOG_INFO("removing fw user %u rule", uid);
            __user_unhash(fu);
            user_free(fu);
        }
    }
    /* return success if no record found */
    table_unlock();
    return err;
}

int fw_table_delete(const fw_conf *c)
{
    switch(c->type)  {
    case FW_CONF_RULE:
        return delete_rule(c->rule.path, c->rule.uid);
    case FW_CONF_USER:
        return delete_user(c->user.uid);
    default:
        LOG_WARN("not supported to delete fw conf of type %u", c->type);
        break;
    }
    return -1;
}

static int __counter_update(fw_conn *conn)
{
    list res;
    nfct_msg *m;
    conn_entry *e;
    conn_counter c;
    int err, cnt = 0;

    if(! (err = nfct_get_conn(init_table.ct, &res, conn->zone, &conn->src, NULL)))  {
        err = -1;
        list_for_each_nfct_msg(m, &res)  {
            if(! m->entry)  {
                LOG_WARN("unrecognized ct info retrieved, ignored");
                continue;
            }
            cnt++;
            e = m->entry;
            if(nfct_conn_get_counter(e, &c))  {
                LOG_WARN("counter info not available, confirm enabled?");
                break;
            }
            if(cnt > 1)  {
                LOG_ERROR("should have retrived no more than one ct info!");
                break;
            }
            conn->counter.orig_pkts = c.orig_pkts;
            conn->counter.orig_bytes = c.orig_bytes;
            conn->counter.rep_pkts = c.rep_pkts;
            conn->counter.rep_bytes = c.rep_bytes;
            err = 0;
        }list_end;
        nfct_msg_list_free(&res);
    }else if(err == ENOENT)  {
        /* connection already destroyed, no need to update, make as
           succeded */
        err = 0;
    }
    return err;
}

static inline void counter_add(fw_counter *to, const fw_counter *from)
{
    to->orig_pkts += from->orig_pkts;
    to->orig_bytes += from->orig_bytes;
    to->rep_pkts += from->rep_pkts;
    to->rep_bytes += from->rep_bytes;
}

static void __flush_counter(fw_counter *counter)
{
    fw_conn *conn;
    fw_proc *proc;
    hlist_head *h;
    hlist *pos;
    size_t i;

    *counter = init_table.counter;
    for(i = 0; i < init_table.conn_sz; i++)  {
        h = &init_table.conn_table[i];
        hlist_for_each_entry(conn, pos, h, node)  {
            __counter_update(conn);
            counter_add(counter, &conn->counter);
        }
    }
    for(i = 0; i < init_table.proc_sz; i++)  {
        h = &init_table.proc_table[i];
        hlist_for_each_entry(proc, pos, h, node)  {
            counter_add(counter, &proc->counter);
        }
    }
}

void fw_table_for_each(fw_rule_cb cb, void *ud)
{
    fw_counter counter;
    fw_conf c;
    fw_prog *fp;
    fw_ident *fi;
    fw_user *fu;
    fw_proc *proc;
    fw_conn *conn;
    hlist_head *h;
    hlist *pos;
    size_t i;

    table_lock();
    __flush_counter(&counter);
    for(c.type = FW_CONF_RULE, h = init_table.prog_table, i = 0;
        i < init_table.prog_sz; i++, h++)  {
        hlist_for_each_entry(fp, pos, h, node)  {
            c.rule.path = fp->path;
            c.rule.csum = fp->csum;
            c.rule.sz = fp->sz;
            list_for_each_entry(fi, &fp->ident, prog_entry)  {
                c.rule.counter = fi->counter;
                c.rule.uid = fi->uid;
                c.rule.action = fi->action.action;
                list_for_each_entry(proc, &fi->procs, ident_entry)  {
                    counter_add(&c.rule.counter, &proc->counter);
                    branch_for_each_leaf_entry(conn, &proc->conns, proc_entry)  {
                        counter_add(&c.rule.counter, &conn->counter);
                    }branch_for_each_entry_end;
                }
                if(! cb(&c, ud))
                    goto out;
            }
        }
    }

    for(c.type = FW_CONF_USER, h = init_table.user_table, i = 0;
        i < init_table.user_sz; i++, h++)  {
        hlist_for_each_entry(fu, pos, h, node)  {
            c.user.uid = fu->uid;
            c.user.ngrps = fu->ngrps;
            c.user.grps = fu->gid;
            c.user.name = fu->name;
            c.user.counter = fu->counter;
            list_for_each_entry(proc, &fu->procs, user_entry)  {
                counter_add(&c.user.counter, &proc->counter);
                branch_for_each_leaf_entry(conn, &proc->conns, proc_entry)  {
                    counter_add(&c.user.counter, &conn->counter);
                }branch_for_each_entry_end;
            }
            if(! cb(&c, ud))
                goto out;
        }
    }

    c.type = FW_CONF_COUNTER;
    c.counter = counter;
    cb(&c, ud);
 out:
    table_unlock();
}

void fw_table_for_each_verd(fw_verd_cb cb, void *ud)
{
    fw_verd_grp *grp;
    fw_obj fobj;

    table_lock();
    list_for_each_entry(grp, &init_table.verd, list)  {
        fobj.id = grp->id;
        fobj.ts = grp->ts;
        fobj.fos = &grp->fos;
        if(! cb(&fobj, ud))
            break;
    }
    table_unlock();
}

void fw_table_verd_refresh(void)
{
    fw_verd_grp *grp;
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += VERDICT_DEBOUNCE_TIMER;
    table_lock();
    list_for_each_entry(grp, &init_table.verd, list)  {
        grp->ts = ts;
    }
    table_unlock();
}

static int __conn_update_mark(fw_conn *con, __u32 mark)
{
    nfct_msg *msg = nfct_msg_new(con->src.src.l3num, 0);
    int err;

    if(! msg)  {
        LOG_EMERG("unable to alloc nfct msg to update mark");
        return -1;
    }
    nfct_msg_set_zone(msg, con->zone);
    nfct_msg_set_src_tuple(msg, &con->src);
    nfct_msg_set_mark(msg, mark);
    if((err = nfct_set_conn(init_table.ct, msg, 0)))
        LOG_WARN("unable to update mark to conntrack:%d", err);
    return err;
}

static int __conn_setup(fw_conn *con, sk_entry *sk, list *fos)
{
    fw_proc *proc;
    fw_ident *fi;
    fw_prog *fp;
    fw_user *fu;
    fd_owner *fo;

    __conn_update_mark(con, con->mark);
    list_for_each_entry(fo, fos, list)  {
        if(! (proc = __proc_lookup(fo->pid)))  {
            if((proc = proc_new(fo)))  {
                if(! (fi = __ident_lookup(fo->euid, fo->exe)))  {
                    if(! (fp = __prog_lookup(fo->exe)))  {
                        fp = prog_new_from_fo(fo);
                        if(! fp || __prog_insert(fp))  {
                            if(fp)
                                prog_free(fp);
                            proc_free(proc);
                            LOG_EMERG("unable to initiate new fw prog");
                            return -1;
                        }
                    }

                    fi = ident_new(fo->euid, fp);
                    if(! fi || __ident_insert(fi))  {
                        if(fi)
                            ident_free(fi);
                        proc_free(proc);
                        LOG_EMERG("unable to initiate or insert new fw ident");
                        return -1;
                    }
                }

                if(! (fu = __user_lookup(fo->euid)))  {
                    fu = user_new(NULL, fo->euid, fo->ngrps, fo->grps);
                    if(! fu || __user_insert(fu))  {
                        if(fu)
                            user_free(fu);
                        proc_free(proc);
                        LOG_EMERG("unable to initiate or insert new fw user");
                        return -1;
                    }
                }

                list_append(&fu->procs, &proc->user_entry);
                proc->ident = fi;
                list_append(&fi->procs, &proc->ident_entry);
                __proc_insert(proc);
            }else  {
                LOG_EMERG("unable to initiate new fw proc");
                return -1;
            }
        }
        leaf_attach(&con->proc_entry, &proc->conns);
    }
    return 0;
}

static void __conn_update(conn_entry *e, sk_entry *sk, list *fos)
{
    conn_tuple src;
    fw_conn *con;
    __u16 zone = nfct_conn_zone(e);

    if(nfct_conn_get_src_tuple(e, &src))  {
        LOG_ERROR("should never fail to retrive ct tuple");
        return;
    }

    if(! (con = __conn_lookup(&src, zone)))  {
        if(! (con = conn_alloc(&src, zone)))  {
            LOG_EMERG("fail to record new fw conn");
            return;
        }
        if(sk)
            con->ino = sk->info->idiag_inode;
        if(__conn_insert(con))  {
            LOG_ERROR("shouldn't have failed to insert fw conn");
            conn_free(con);
            return;
        }
        if(__conn_setup(con, sk, fos))  {
            __conn_release(con);
            conn_free(con);
        }
    }else  {
        /* or check the ct id? */
        if(con->mark == nfct_conn_mark(e))
            return;
        __conn_update_mark(con, con->mark);
    }
}

static inline int proc_validate(pid_t pid, ino_t ino)
{
    struct stat st;
    char path[30];

    sprintf(path, "/proc/%u", pid);
    if(! stat(path, &st) && st.st_ino == ino)
        return 0;
    return -1;
}

static void __proc_delete(fw_proc *proc)
{
    fw_user *fu;

    __fw_verd_release(&proc->action);
    list_delete(&proc->ident_entry);
    list_delete(&proc->user_entry);
    if(proc->ident)
        counter_add(&proc->ident->counter, &proc->counter);
    if((fu = __user_lookup(proc->uid)))
       counter_add(&fu->counter, &proc->counter);
    counter_add(&init_table.counter, &proc->counter);
    __proc_release(proc);
    proc_free(proc);
}

static int __gc()
{
    fw_proc *proc, *n;
    int cnt = 0, cont = 0;

    /* currently there's only one condition that fw proc won't be
       freed, that is when the proc was denied to access network, no
       connection shall be establsihed and won't notify fw table about
       it, where fw proc was validate and freed */
    list_for_each_entry_safe(proc, n, &init_table.procs, list)  {
        /* ?? depend on conntrack to free */
        if(proc->conns.cnt > 0)
            continue;
        if(proc_validate(proc->pid, proc->magic))  {
            __proc_delete(proc);
            cnt++;
            continue;
        }
        cont = 1;
    }

    if(cont)  {
        if(init_table.gc_timeout + 1 < arraysize(gc_timeout))
            init_table.gc_timeout++;
        __timer_sched(&init_table.gc_timer, 0, gc_timeout[init_table.gc_timeout]);
        LOG_INFO("GC: %d recollected, sched in %d ms", cnt, gc_timeout[init_table.gc_timeout]);
    }else  {
        LOG_INFO("GC: %d recollected, stop", cnt);
    }
    return cont;
}

static int gc(void *ud)
{
    int cont;

    table_lock();
    cont = __gc();
    table_unlock();
    return cont;
}

static void __conn_delete(conn_entry *e)
{
    conn_tuple src;
    fw_conn *con;
    __u16 zone = nfct_conn_zone(e);
    fw_proc *proc;
    conn_counter counter;
    int counter_avail;

    if(nfct_conn_get_src_tuple(e, &src))  {
        LOG_ERROR("should never fail to retrive ct tuple");
        return;
    }

    if(! (con = __conn_lookup(&src, zone)))  {
        LOG_INFO("ignore untracked conntrack");
        return;
    }

    counter_avail = ! nfct_conn_get_counter(e, &counter);
    leaf_for_each_branch_entry(proc, &con->proc_entry, conns)  {
        if(counter_avail)  {
            proc->counter.orig_pkts += counter.orig_pkts;
            proc->counter.orig_bytes += counter.orig_bytes;
            proc->counter.rep_pkts += counter.rep_pkts;
            proc->counter.rep_bytes += counter.rep_bytes;
        }
        if(proc_validate(proc->pid, proc->magic))
            __proc_delete(proc);
    }leaf_for_each_entry_end;

    __conn_release(con);
    conn_free(con);
}

/**
 * any conntrack change should notify fw tables
 * @fos: list of fd_owner related to @ctmsg
 */
void fw_table_conn_changed(nfct_msg *ctmsg, sk_entry *sk, list *fos)
{
    table_lock();
    if(ctmsg->entry)  {
        if(ctmsg->type == IPCTNL_MSG_CT_NEW)
            __conn_update((conn_entry *)ctmsg->entry, sk, fos);
        else if(ctmsg->type == IPCTNL_MSG_CT_DELETE)
            __conn_delete((conn_entry *)ctmsg->entry);
        else
            LOG_WARN("invalid type conntrack message %u notified", ctmsg->type);
    }else  {
        LOG_WARN("not supposed to receive raw ct msg %u", ctmsg->type);
    }
    table_unlock();
}

void fw_table_get_stat(fw_stat *st)
{
    table_lock();
    memcpy(st, &init_table.stat, sizeof(*st));
    table_unlock();
}

int fw_table_get_throttle_proc(pid_t pid)
{
    fw_proc *proc;
    int throttled = 0;

    table_lock();
    if((proc = __proc_lookup(pid)))  {
        if(proc_validate(proc->pid, proc->magic))
            __proc_delete(proc);
        else
            throttled = !! (proc->action.flags & VERDICT_F_THROTTLE);
    }
    table_unlock();
    return throttled;
}

static inline int __throttle_conn(fw_conn *conn)
{
    conn->flags |= CONN_F_THROTTLE;
    return __conn_update_mark(conn, BLACK_HOLE);
}

static inline int __unthrottle_conn(fw_conn *conn)
{
    conn->flags &= ~CONN_F_THROTTLE;
    return __conn_update_mark(conn, conn->mark);
}

static int __throttle_proc(fw_proc *proc)
{
    fw_conn *conn;

    proc->action.flags |= VERDICT_F_THROTTLE;
    branch_for_each_leaf_entry(conn, &proc->conns, proc_entry)  {
        if(! (conn->flags & CONN_F_THROTTLE))  {
            if(__throttle_conn(conn))
                LOG_WARN("error throttle fw conn");
        }
    }branch_for_each_entry_end;
    /* might fail to commit the operation, but return success as all
       flags set  */
    return 0;
}

static int __unthrottle_proc(fw_proc *proc)
{
    fw_conn *conn;
    fw_proc *p;

    proc->action.flags &= ~ VERDICT_F_THROTTLE;
    branch_for_each_leaf_entry(conn, &proc->conns, proc_entry)  {
        if(conn->flags & CONN_F_THROTTLE)  {
            leaf_for_each_branch_entry(p, &conn->proc_entry, conns)  {
                if(p->action.flags & VERDICT_F_THROTTLE)
                    goto skip;
            }leaf_for_each_entry_end;
            if(__unthrottle_conn(conn))
                LOG_WARN("error unthrottle fw conn");
        }
    skip:;
    }branch_for_each_entry_end;
    return 0;
}

static int __throttle_ident(fw_ident *fi)
{
    fw_proc *proc;

    fi->action.flags |= VERDICT_F_THROTTLE;
    list_for_each_entry(proc, &fi->procs, ident_entry)  {
        if(proc_validate(proc->pid, proc->magic))  {
            __proc_delete(proc);
            LOG_INFO("ignored stale proc %u, deleted", proc->pid);
        }else if(! (proc->action.flags & VERDICT_F_THROTTLE))  {
            __throttle_proc(proc);
        }
    }
    return 0;
}

static int __unthrottle_ident(fw_ident *fi)
{
    fw_proc *proc;
    fw_user *fu;

    fi->action.flags &= ~ VERDICT_F_THROTTLE;
    list_for_each_entry(proc, &fi->procs, ident_entry)  {
        if(proc_validate(proc->pid, proc->magic))  {
            __proc_delete(proc);
            LOG_INFO("ignored stale proc %u, deleted", proc->pid);
        }else if(proc->action.flags & VERDICT_F_THROTTLE)  {
            fu = __user_lookup(proc->uid);
            if(! fu || ! (fu->flags & VERDICT_F_THROTTLE))
                __unthrottle_proc(proc);
        }
    }
    return 0;
}

static int __throttle_user(fw_user *fu)
{
    fw_proc *proc;

    fu->flags |= VERDICT_F_THROTTLE;
    list_for_each_entry(proc, &fu->procs, user_entry)  {
        if(proc_validate(proc->pid, proc->magic))  {
            __proc_delete(proc);
            LOG_INFO("ignore stale proc %u, deleted", proc->pid);
        }else if(! (proc->action.flags & VERDICT_F_THROTTLE))  {
            __throttle_proc(proc);
        }
    }
    return 0;
}

static int __unthrottle_user(fw_user *fu)
{
    fw_proc *proc;
    fw_ident *fi;

    fu->flags &= ~ VERDICT_F_THROTTLE;
    list_for_each_entry(proc, &fu->procs, user_entry)  {
        if(proc_validate(proc->pid, proc->magic))  {
            __proc_delete(proc);
            LOG_INFO("ignored stale proc %u, deleted", proc->pid);
        }else if(proc->action.flags & VERDICT_F_THROTTLE)  {
            fi = proc->ident;
            if(! fi || ! (fi->action.flags & VERDICT_F_THROTTLE))
                __unthrottle_proc(proc);
        }
    }
    return 0;
}

int fw_table_set_throttle_proc(pid_t pid, int stat)
{
    fw_proc *proc;
    int err = -1;

    table_lock();
    if((proc = __proc_lookup(pid)))  {
        if(proc_validate(proc->pid, proc->magic))  {
            __proc_delete(proc);
            LOG_INFO("ignored stale proc %u, deleted", proc->pid);
        }else  {
            if(stat && ! (proc->action.flags & VERDICT_F_THROTTLE))
                err = __throttle_proc(proc);
            else if(! stat && (proc->action.flags & VERDICT_F_THROTTLE))
                err =__unthrottle_proc(proc);
            else
                err = 0;
        }
    }
    table_unlock();
    return err;
}

int fw_table_get_throttle_prog(const char *path, uid_t uid)
{
    fw_ident *fi;
    int throttled = 0;

    table_lock();
    if((fi = __ident_lookup(uid, path)))
        throttled = !! (fi->action.flags & VERDICT_F_THROTTLE);
    table_unlock();
    return throttled;
}

int fw_table_set_throttle_prog(const char *path, uid_t uid, int stat)
{
    fw_ident *fi;
    int err = -1;

    table_lock();
    if((fi = __ident_lookup(uid, path)))  {
        if(stat && ! (fi->action.flags & VERDICT_F_THROTTLE))  {
            err = __throttle_ident(fi);
        }else if(! stat && (fi->action.flags & VERDICT_F_THROTTLE))  {
            err = __unthrottle_ident(fi);
        }else  {
            err = 0;
        }
    }
    table_unlock();
    return err;
}

int fw_table_get_throttle_user(uid_t uid)
{
    fw_user *fu;
    int throttled = 0;

    table_lock();
    if((fu = __user_lookup(uid)))
        throttled = !! (fu->flags & VERDICT_F_THROTTLE);
    table_unlock();
    return throttled;
}

int fw_table_set_throttle_user(uid_t uid, int stat)
{
    fw_user *fu;
    int err = -1;

    table_lock();
    if((fu = __user_lookup(uid)))  {
        if(stat && ! (fu->flags & VERDICT_F_THROTTLE))
            err = __throttle_user(fu);
        else if(! stat && (fu->flags & VERDICT_F_THROTTLE))
            err = __unthrottle_user(fu);
        else
            err = 0;
    }
    table_unlock();
    return err;
}

int fw_table_get_throttle_conn(__u16 zone, const conn_tuple *src)
{
    fw_conn *conn;
    int throttled = 0;

    table_lock();
    if((conn = __conn_lookup(src, zone)))
        throttled = !! (conn->flags & CONN_F_THROTTLE);
    table_unlock();
    return throttled;
}

int fw_table_set_throttle_conn(__u16 zone, const conn_tuple *src, int stat)
{
    fw_conn *conn;
    int err = -1;

    table_lock();
    if((conn = __conn_lookup(src, zone)))  {
        if(stat && ! (conn->flags & CONN_F_THROTTLE))
            err = __throttle_conn(conn);
        else if(! stat && (conn->flags & CONN_F_THROTTLE))
            err = __unthrottle_conn(conn);
        else
            err = 0;
    }
    table_unlock();
    return err;
}

static void __proc_for_each_conn(fw_proc *proc, fw_conn_cb cb, void *ud)
{
    fw_conn *conn;

    branch_for_each_leaf_entry(conn, &proc->conns, proc_entry)  {
        if(! cb(conn->zone, &conn->src, ud))
            break;
    }branch_for_each_entry_end;
}

void fw_table_for_each_conn_of_proc(pid_t pid, fw_conn_cb cb, void *ud)
{
    fw_proc *proc;

    table_lock();
    if((proc = __proc_lookup(pid)))
        __proc_for_each_conn(proc, cb, ud);
    table_unlock();
}

void fw_table_for_each_conn_of_prog(const char *path, uid_t uid, fw_conn_cb cb, void *ud)
{
    fw_ident *fi;
    fw_proc *proc;

    table_lock();
    if((fi = __ident_lookup(uid, path)))  {
        list_for_each_entry(proc, &fi->procs, ident_entry)  {
            __proc_for_each_conn(proc, cb, ud);
        }
    }
    table_unlock();
}

void fw_table_for_each_conn_of_user(uid_t uid, fw_conn_cb cb, void *ud)
{
    fw_user *fu;
    fw_proc *proc;

    table_lock();
    if((fu = __user_lookup(uid)))  {
        list_for_each_entry(proc, &fu->procs, user_entry)  {
            __proc_for_each_conn(proc, cb, ud);
        }
    }
    table_unlock();
}

int fw_table_get_conn_counter(__u16 zone, const conn_tuple *src, fw_counter *counter)
{
    fw_conn *conn;
    int err = -1;

    table_lock();
    if((conn = __conn_lookup(src, zone)))
        if(! (err = __counter_update(conn)))
            *counter = conn->counter;
    table_unlock();
    return err;
}

static int __get_proc_counter(fw_proc *proc, fw_counter *counter)
{
    fw_conn *conn;
    int err = -1;

    *counter = proc->counter;
    branch_for_each_leaf_entry(conn, &proc->conns, proc_entry)  {
        if(! __counter_update(conn))  {
            counter_add(counter, &conn->counter);
            err = 0;
        }
    }branch_for_each_entry_end;
    return err;
}

int fw_table_get_proc_counter(pid_t pid, fw_counter *counter)
{
    fw_proc *proc;
    int err = -1;

    table_lock();
    if((proc = __proc_lookup(pid)))
        err = __get_proc_counter(proc, counter);
    table_unlock();
    return err;
}

int fw_table_get_prog_counter(const char *path, uid_t uid, fw_counter *counter)
{
    fw_ident *fi;
    fw_proc *proc;
    fw_counter tmp;
    int err = -1;

    table_lock();
    if((fi = __ident_lookup(uid, path)))  {
        *counter = fi->counter;
        list_for_each_entry(proc, &fi->procs, ident_entry)  {
            if(! (err = __get_proc_counter(proc, &tmp)))
                counter_add(counter, &tmp);
        }
    }
    table_unlock();
    return err;
}

int fw_table_get_user_counter(uid_t uid, fw_counter *counter)
{
    fw_user *fu;
    fw_proc *proc;
    fw_counter tmp;
    int err = -1;

    table_lock();
    if((fu = __user_lookup(uid)))  {
        *counter = fu->counter;
        list_for_each_entry(proc, &fu->procs, user_entry)  {
            if(! (err = __get_proc_counter(proc, &tmp)))
                counter_add(counter, &tmp);
        }
    }
    table_unlock();
    return err;
}

void fw_table_get_global_counter(fw_counter *counter)
{
    table_lock();
    __flush_counter(counter);
    table_unlock();
}

void fw_table_for_each_prog(int flags, fw_prog_cb cb, void *ud)
{
    fw_prog *fp;
    fw_ident *fi;
    hlist_head *h;
    hlist *pos;
    size_t i;

    table_lock();
    for(i = 0; i < init_table.prog_sz; i++)  {
        h = &init_table.prog_table[i];
        hlist_for_each_entry(fp, pos, h, node)  {
            if(list_empty(&fp->ident))
                continue;
            list_for_each_entry(fi, &fp->ident, prog_entry)  {
                if((flags & ITER_F_ACTIVE) && list_empty(&fi->procs))
                    continue;
                if(! cb(fp->path, fi->uid, fi->action.action, ud))
                    goto out;
            }
        }
    }
    out:
    table_unlock();
}

void fw_table_for_each_user(int flags, fw_user_cb cb, void *ud)
{
    fw_user *fu;
    hlist_head *h;
    hlist *pos;
    size_t i;

    table_lock();
    for(i = 0; i < init_table.user_sz; i++)  {
        h = &init_table.user_table[i];
        hlist_for_each_entry(fu, pos, h, node)  {
            if((flags & ITER_F_ACTIVE) && list_empty(&fu->procs))
                continue;
            if(! cb(fu->name, fu->uid, ud))
                goto out;
        }
    }
 out:
    table_unlock();
}

void fw_table_for_each_proc(fw_proc_cb cb, void *ud)
{
	fw_proc *proc;
	hlist_head *h;
	hlist *pos;
	size_t i;

	table_lock();
	for(i = 0; i < init_table.proc_sz; i++)  {
		h = &init_table.proc_table[i];
		hlist_for_each_entry(proc, pos, h, node)  {
			if(! cb(proc->exe, proc->pid, proc->uid, proc->action.action, ud))
				goto out;
		}
	}
 out:
	table_unlock();
}

void fw_table_for_each_proc_of_prog(const char *path, fw_proc_cb cb, void *ud)
{
    fw_prog *fp;
    fw_ident *fi;
    fw_proc *proc;

    table_lock();
    if((fp = __prog_lookup(path)))  {
        list_for_each_entry(fi, &fp->ident, prog_entry)  {
            list_for_each_entry(proc, &fi->procs, ident_entry)  {
                if(! cb(proc->exe, proc->pid, proc->uid, proc->action.action, ud))
                    break;
            }
        }
    }
    table_unlock();
}

void fw_table_for_each_proc_of_user(uid_t uid, fw_proc_cb cb, void *ud)
{
    fw_user *fu;
    fw_proc *proc;

    table_lock();
    if((fu = __user_lookup(uid)))  {
        list_for_each_entry(proc, &fu->procs, user_entry)  {
            if(! cb(proc->exe, proc->pid, proc->uid, proc->action.action, ud))
                break;
        }
    }
    table_unlock();
}

int fw_table_get_def_action(void)
{
    /* TODO: impl */
    return -1;
}

int fw_table_set_def_action(int action)
{
    /* TODO: impl. */
    return -1;
}

