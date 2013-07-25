/*
 * fw_table.h Cactus FW tables
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

#ifndef __FW_TABLE_H
#define __FW_TABLE_H

#include <time.h>
#include <sys/types.h>
#include <linux/types.h>

#include "util.h"
#include "branch.h"
#include "msg_base.h"           /* verdict defined */
#include "nfct.h"               /* conn_tuple defined */
#include "fd_lookup.h"          /* fd_owner defined */

__BEGIN_DECLS

typedef struct _fw_verd fw_verd; /* verdict info */
typedef struct _fw_verd_grp fw_verd_grp;

typedef struct _fw_counter fw_counter;

typedef struct _fw_conn fw_conn; /* A network connection */
typedef struct _fw_prog fw_prog; /* A host program */
typedef struct _fw_ident fw_ident; /* User ident of a process */
typedef struct _fw_proc fw_proc; /* A host process */
typedef struct _fw_user fw_user; /* A host user */

typedef struct _fw_obj fw_obj;  /* A FW verification object */
typedef struct _fw_cb fw_cb;    /* FW callbacks */

typedef struct _fw_conf fw_conf; /* A FW config description */

typedef struct _fw_stat fw_stat; /* FW statistic */

enum{
    VERDICT_OBJ_IDENT,
    VERDICT_OBJ_PROC,
};

struct _fw_verd{
    list list;
#define VERDICT_OBJ_SHIFT (8 * 3)
#define VERDICT_OBJ_MASK 0x0F

#define VERDICT_F_VERD 1          /* queued for verdict */
#define VERDICT_F_THROTTLE (1<<1) /* NW throttled */
    int flags;
    int action;
    fw_verd_grp *grp;
};

struct _fw_verd_grp{
    list list;
    list verds;
    list fos;
    void *ctx;
    struct timespec ts;
    __u64 id;
};

struct _fw_counter{
    __u64 orig_pkts;
    __u64 orig_bytes;
    __u64 rep_pkts;
    __u64 rep_bytes;
};

struct _fw_conn{
    hlist node;
    __u16 zone;
    conn_tuple src;
#define CONN_F_THROTTLE 1
    int flags;
    __u32 mark;
    /* for owners verification */
    ino_t ino;
    /* one conn may be shared by multiple proc */
    leaf proc_entry;
    fw_counter counter;
};

struct _fw_prog{
    hlist node;
    /* md5 signature */
    char csum[16];
    /* file sz signature */
    size_t sz;
    list ident;
    char path[0];
};

struct _fw_ident{
    hlist node;
    list prog_entry;
    list procs;
    fw_prog *prog;
    fw_verd action;
    uid_t uid;
    fw_counter counter;
};

struct _fw_proc{
    hlist node;
    fw_verd action;
    pid_t pid, ppid, sid;
    uid_t uid;
    gid_t gid;
    /* proc dir ino */
    ino_t magic;
    fw_ident *ident;
    list list;
    /* prog belong to, one prog may spawn multiple proc */
    list ident_entry;
    /* user belong to, one user may spawn multiple proc */
    list user_entry;
    /* connections belong to this proc, one proc may issue multiple conn */
    branch conns;
    fw_counter counter;
	char exe[0];
};

struct _fw_user{
    hlist node;
    uid_t uid;
    size_t ngrps;
    gid_t *gid;
    int flags;
    list procs;
    fw_counter counter;
    char name[0];
};

struct _fw_obj{
    __u64 id;
    struct timespec ts;
    list *fos;
};

struct _fw_cb{
    void (*verdict_req)(fw_obj *fobj, void *ud);
    /* set NULL to ignore */
    void (*verdict_res)(__u64 rid, void *ctx, int verd, void *ud);
    void *req_ud;
    void *res_ud;
};

enum{
    FW_CONF_RULE,
    FW_CONF_USER,
    FW_CONF_COUNTER,
};

struct _fw_conf{
    int type;
    union{
        struct{
            uid_t uid;
            char *path;
            char *csum;
            size_t sz;
            int action;
            fw_counter counter;
        }rule;
        struct{
            uid_t uid;
            unsigned int ngrps;
            gid_t *grps;
            char *name;
            fw_counter counter;
        }user;
        fw_counter counter;
    };
};

struct _fw_stat{
    size_t conns;
    size_t progs;
    size_t idents;
    /* not runtime accurate, updated asynchronously */
    size_t procs;
    size_t users;
};

/**
 * return 0 to break iteration.
 */
typedef int (*fw_rule_cb)(const fw_conf *r, void *ud);

/**
 * return 0 to break iteration
 */
typedef int (*fw_verd_cb)(fw_obj *fobj, void *ud);

/**
 * return 0 to break iteration
 */
typedef int (*fw_conn_cb)(__u16 zone, const conn_tuple *src, void *ud);

/**
 * @flags: unused currently
 */
int fw_table_init(const fw_cb *cb, nfct_t *ct, int flags);

/**
 * @ctx: used by caller, fw table doesn't parse it.
 * @vid: verdict request id to return if @fos is going to be pending
 * for front-end's final decision, otherwise undefined, verdict
 * returned on return.
 * NOTE:
 * fw table will take over the ownership of @fos if verdict request
 * needed
 */
int fw_table_walk(list *fos, void *ctx, __u64 *vid);

int fw_table_verd(__u64 rid, int verdict);

/**
 * NOTE: the action that disables the targets' network will disconnect
 * the its their network connection immediately
 * function will fail to requested object does note exist in fw table.
 */
int fw_table_set_proc_action(pid_t pid, int action);
int fw_table_get_proc_action(pid_t pid, int *action);

int fw_table_set_prog_action(const char *prog, uid_t uid, int action);
int fw_table_get_prog_action(const char *prog, uid_t uid, int *action);

int fw_table_insert(const fw_conf *r);
int fw_table_delete(const fw_conf *r);

/**
 * NOTE: *NEVER* call any other fw_table functions inside @cb,
 * deadlock otherwise.
 */
void fw_table_for_each(fw_rule_cb cb, void *ud);

/**
 * iterate on pending verdicts
 */
void fw_table_for_each_verd(fw_verd_cb cb, void *ud);

/**
 * refresh all pending verdict debounce timer
 */
void fw_table_verd_refresh(void);

/**
 * any conntrack change should notify fw tables
 * @fos: list of fd_owner related to @ctmsg
 */
void fw_table_conn_changed(nfct_msg *ctmsg, sk_entry *sk, list *fos);

void fw_table_get_stat(fw_stat *st);

/**
 * NOTE: if target throttled, NW connection is possible, but not for
 * data communication after that
 */
int fw_table_get_throttle_proc(pid_t pid);
int fw_table_set_throttle_proc(pid_t pid, int stat);

int fw_table_get_throttle_prog(const char *path, uid_t uid);
int fw_table_set_throttle_prog(const char *path, uid_t uid, int stat);

int fw_table_get_throttle_user(uid_t uid);
int fw_table_set_throttle_user(uid_t uid, int stat);

int fw_table_get_throttle_conn(__u16 zone, const conn_tuple *src);
int fw_table_set_throttle_conn(__u16 zone, const conn_tuple *src, int stat);

/**
 * NOTE: 1. never call fw table functions inside @cb, or dead lock
 * happens, 2. may have duplicating items if connection shared between
 * procs.
 */
void fw_table_for_each_conn_of_proc(pid_t pid, fw_conn_cb cb, void *ud);
void fw_table_for_each_conn_of_prog(const char *path, uid_t uid, fw_conn_cb cb, void *ud);
void fw_table_for_each_conn_of_user(uid_t uid, fw_conn_cb cb, void *ud);

static inline int fw_table_set_counter_enable(int stat)
{
    return file_write("/proc/sys/net/netfilter/nf_conntrack_acct",
                      stat ? "1" : "0", -1);
}

static inline int fw_table_get_counter_enable(int *stat)
{
    return file_read_int("/proc/sys/net/netfilter/nf_conntrack_acct", stat);
}

/**
 * NOTE:
 * 
 * 1. The counter info is totally based on kernel ct module counter
 * info.
 * 
 * 2. it's probably not exactly the same as the ISP's account info.
 *
 * 3. As sockets can be shared between processes(even through not
 * happen very frequently), there's no way to distinguish data source,
 * here the data is counted by all the socket owners(processes).
 *
 * 4. After all, it should accurate enough.
 */
int fw_table_get_conn_counter(__u16 zone, const conn_tuple *src, fw_counter *counter);
int fw_table_get_proc_counter(pid_t pid, fw_counter *counter);
int fw_table_get_prog_counter(const char *path, uid_t uid, fw_counter *counter);
int fw_table_get_user_counter(uid_t uid, fw_counter *counter);

/**
 * NOTE: this will flush all connections counter info.
 */
void fw_table_get_global_counter(fw_counter *counter);

/**
 * return 0 to break iteration
 */
typedef int (*fw_prog_cb)(const char *path, uid_t uid, int action, void *ud);
typedef int (*fw_user_cb)(const char *name, uid_t uid, void *ud);
typedef int (*fw_proc_cb)(const char *path, pid_t pid, uid_t uid, int action, void *ud);

#define ITER_F_ACTIVE 1         /* iterate on active objects(accessing
                                   network */

void fw_table_for_each_prog(int flags, fw_prog_cb cb, void *ud);
void fw_table_for_each_user(int flags, fw_user_cb cb, void *ud);
void fw_table_for_each_proc(fw_proc_cb cb, void *ud);
void fw_table_for_each_proc_of_prog(const char *path, fw_proc_cb cb, void *ud);
void fw_table_for_each_proc_of_user(uid_t uid, fw_proc_cb cb, void *ud);

/* FIXME: ?? */
int fw_table_get_def_action(void);
int fw_table_set_def_action(int action);

__END_DECLS

#endif  /* ! __FW_TABLE_H */

