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

#ifndef __FD_LOOKUP_H
#define __FD_LOOKUP_H

#include <sys/types.h>

#include "util.h"
#include "nfct.h"
#include "sock_stat.h"

__BEGIN_DECLS

typedef struct _fd_owner fd_owner;

struct _fd_owner{
    list list;
    uid_t euid;
    gid_t egid;
    unsigned int ngrps;
    gid_t *grps;
    pid_t pid, ppid, tgid, tracerpid, sid;
    ino_t ino;                  /* proc dir ino */
    int len;
    char exe[0];
};

#define FD_PIPE 1
#define FD_SOCK 2

int lookup_fos_from_path(list *owners, const char *path);

int lookup_fos_from_ino(list *owners, int type, ino_t ino);

sk_entry *lookup_sk_from_ct(const nfct_msg *msg);

static inline int lookup_fos_from_sk(list *owners, const sk_entry *sk)
{
    return lookup_fos_from_ino(owners, FD_SOCK, sk->info->idiag_inode);
}

static inline int lookup_fos_from_ct(list *owners, const nfct_msg *msg)
{
    sk_entry *sk = lookup_sk_from_ct(msg);
    int res = -1;

    if(sk)  {
        res = lookup_fos_from_sk(owners, sk);
        sk_entry_free(sk);
    }
    return res;
}

static void fd_owners_free(list *l)
{
    fd_owner *fo, *n;

    list_for_each_entry_safe(fo, n, l, list)  {
        list_delete(&fo->list);
        if(fo->grps)
            free(fo->grps);
        free(fo);
    }
}

__END_DECLS

#endif  /* __FD_LOOKUP_H */

