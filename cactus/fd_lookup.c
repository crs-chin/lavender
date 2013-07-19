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

#include <limits.h>
#include <stdlib.h>
#include <alloca.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <dirent.h>

#include "util.h"
#include "nfct.h"
#include "sock_stat.h"
#include "fd_lookup.h"


static inline int is_task(const char *name)
{
    const char *p;

    for(p = name; *p; p++)  {
        if(*p < '0' || *p > '9')
            return 0;
    }
    return 1;
}

static inline char *check_eol(char *p, int len)
{
    while(len && *p != '\n')  {
        p++;
        len--;
    }
    return len ? ++p : NULL;
}

static int parse_grps(char *p, unsigned int *cnt, gid_t **array)
{
    int sz = 15, n = 0;
    gid_t *a, *pa, *t;

    if(! (a = (gid_t *)malloc(sizeof(gid_t) * sz)))
        return -1;

    for(pa = a; *p != '\n' && *(p + 1) != '\n'; n++)  {
        if(n == sz)  {
            sz += 10;
            if(! (t = realloc(a, sizeof(gid_t) * sz)))  {
                free(a);
                return -1;
            }
            a = t;
            pa = a + n;
        }
        *pa++ = strtol(p, &p, 10);
    }

    if(n == 0)  {
        free(a);
        a = NULL;
    }

    *cnt = n;
    *array = a;
    return 0;
}

static int parse_status(fd_owner *fo, DIR *dir)
{
    char buf[1024], *p = buf, *tmp;
    int fd, len, res, i;

    if((fd = openat(dirfd(dir), "status", O_RDONLY, 0)) < 0)
        return -1;

    for(len = 0, i = 0;;)  {
        if((res = read(fd, p, sizeof(buf) - (p - buf))) <= 0)
            break;
        len += res;
        for(;;)  {
            if(! (tmp = check_eol(p, len - (p - buf))))
                break;
            switch(i)  {
            case 0:
            case 1:
            case 8:
                p = tmp;
                i++;
                continue;
            case 2:
                if(strncmp("Tgid:\t", p, strlen("Tgid:\t")))
                    goto fail_parse;
                p += strlen("Tgid:\t");
                fo->tgid = atol(p);
                p = tmp;
                i++;
                continue;
            case 3:
                if(strncmp("Pid:\t", p, strlen("Pid:\t")))
                    goto fail_parse;
                p += strlen("Pid:\t");
                fo->pid = atol(p);
                p = tmp;
                i++;
                continue;
            case 4:
                if(strncmp("PPid:\t", p, strlen("PPid:\t")))
                    goto fail_parse;
                p += strlen("PPid:\t");
                fo->ppid = atol(p);
                p = tmp;
                i++;
                continue;
            case 5:
                if(strncmp("TracerPid:\t", p, strlen("TracerPid:\t")))
                    goto fail_parse;
                p += strlen("TracerPid:\t");
                fo->tracerpid = atol(p);
                p = tmp;
                i++;
                continue;
            case 6:
                if(strncmp("Uid:\t", p, strlen("Uid:\t")))
                    goto fail_parse;
                p += strlen("Uid:\t");
                strtol(p, &p, 10);
                if(*p++ != '\t')
                    goto fail_parse;
                fo->euid = atol(p);
                p = tmp;
                i++;
                continue;
            case 7:
                if(strncmp("Gid:\t", p, strlen("Gid:\t")))
                    goto fail_parse;
                p += strlen("Gid:\t");
                strtol(p, &p, 10);
                if(*p++ != '\t')
                    goto fail_parse;
                fo->egid = atol(p);
                p = tmp;
                i++;
                continue;
            case 9:
                if(strncmp("Groups:\t", p, strlen("Groups:\t")))
                    goto fail_parse;
                p += strlen("Groups:\t");
                if(parse_grps(p, &fo->ngrps, &fo->grps))
                    goto fail_parse;
                close(fd);
                return 0;
            }
        }
        if(p != buf && p - buf < len)  {
            memmove(buf, p, len - (p - buf));
            len -= p - buf;
        }
    }

 fail_parse:
    close(fd);
    return -1;
}

static fd_owner *new_fo(const char *name)
{
    char proc[512] = "/proc/";
    DIR *dir;
    fd_owner *fo, *tmp;
    struct stat st;
    int plen = 127, res;

    strcat(proc, name);
    if(! (dir = opendir(proc)))
        return NULL;

    if(fstat(dirfd(dir), &st) < 0)  {
        closedir(dir);
        return NULL;
    }

    if(! (fo = (fd_owner *)malloc(sizeof(fd_owner) + plen + 1)))  {
        closedir(dir);
        return NULL;
    }

    for(;;)  {
        res = readlinkat(dirfd(dir), "exe", fo->exe, plen);
        if(res == plen)  {
            if(plen < (PATH_MAX - 1))  {
                plen += 128;
                if((tmp = realloc(fo, sizeof(fd_owner) + plen + 1)))  {
                    fo = tmp;
                    continue;
                }
            }
        }

        if(res > 0)
            break;

        closedir(dir);
        free(fo);
        return NULL;
    }

    fo->ino = st.st_ino;
    fo->len = res;
    fo->exe[res] = '\0';
    if((res = parse_status(fo, dir)))  {
        closedir(dir);
        free(fo);
        return NULL;
    }
    closedir(dir);
    return fo;
}

static fd_owner *check_task(const char *name, const char *path, char *tmp, int len)
{
    char fd_path[1024];
    struct dirent *ent;
    fd_owner *fo = NULL;
    DIR *dir;
    int res;

    sprintf(fd_path, "/proc/%s/fd/", name);
    if(! (dir = opendir(fd_path)))
        return NULL;
    while((ent = readdir(dir)))  {
        if(ent->d_name[0] == '.'
           && (ent->d_name[1] == '\0'
               || (ent->d_name[1] == '.'
                   && ent->d_name[2] == '\0')))
            continue;
        if((res = readlinkat(dirfd(dir), ent->d_name, tmp, len)) <= 0)
            continue;
        if(! strncmp(tmp, path, res))  {
            fo = new_fo(name);
            break;
        }
    }
    closedir(dir);
    return fo;
}

int lookup_fos_from_path(list *owners, const char *path)
{
    DIR *dir;
    struct dirent *ent;
    fd_owner *fo;
    char *realp, *tmp;
    int len;

    if(! owners || ! path)
        return -1;
    if(! (realp = realpath(path, NULL)))
        return -1;

    len = strlen(realp);
    tmp = (char *)alloca(len);

    if(! (dir = opendir("/proc")))  {
        free(realp);
        return -1;
    }

    list_init(owners);
    while((ent = readdir(dir)))  {
        if(ent->d_name[0] == '.'
           && (ent->d_name[1] == '\0'
               || (ent->d_name[1] == '.'
                   && ent->d_name[2] == '\0')))
            continue;

        if(! is_task(ent->d_name))
            continue;

        if((fo = check_task(ent->d_name, realp, tmp, len)))
            list_append(owners, &fo->list);
    }
    closedir(dir);
    free(realp);
    return 0;
}

int lookup_fos_from_ino(list *owners, int type, ino_t ino)
{
    char tg[50], tmp[50];
    DIR *dir;
    struct dirent *ent;
    fd_owner *fo;

    if(! owners)
        return -1;

    if(type == FD_PIPE)
        sprintf(tg, "pipe:[%lu]", ino);
    else if(type == FD_SOCK)
        sprintf(tg, "socket:[%lu]", ino);
    else
        return -1;

    if(! (dir = opendir("/proc")))
        return -1;

    list_init(owners);
    while((ent = readdir(dir)))  {
        if(ent->d_name[0] == '.'
           && (ent->d_name[1] == '\0'
               || (ent->d_name[1] == '.'
                   && ent->d_name[2] == '\0')))
            continue;

        if(! is_task(ent->d_name))
            continue;

        if((fo = check_task(ent->d_name, tg, tmp, sizeof(tmp))))
            list_append(owners, &fo->list);
    }
    closedir(dir);
    return 0;
}

sk_entry *lookup_sk_from_ct(const nfct_msg *msg)
{
    const conn_entry *ent;
    conn_tuple src;
    sk_entry *sk = NULL;

    if(! msg || ! msg->entry)
        return NULL;

    ent = (const conn_entry *)msg->entry;
    if(nfct_conn_get_src_tuple(ent, &src))
        return NULL;

    switch(src.src.l3num)  {
    case AF_INET:
        switch(src.dst.protonum)  {
        case IPPROTO_TCP:
            sk = sock_stat_lookup_tcp(src.src.u3.ip,
                                      src.dst.u3.ip,
                                      src.src.u.tcp.port,
                                      src.dst.u.tcp.port,
                                      0);
            break;
        case IPPROTO_UDP:
            sk = sock_stat_lookup_udp_exact(src.src.u3.ip,
                                            src.dst.u3.ip,
                                            src.src.u.udp.port,
                                            src.dst.u.udp.port,
                                            0);
            break;
        case IPPROTO_UDPLITE:
            /* FIXME: impl. */
        default:
            break;
        }
        break;
    case AF_INET6:
        switch(src.dst.protonum)  {
        case IPPROTO_TCP:
            sk = sock_stat_lookup_tcp6(src.src.u3.ip6,
                                       src.dst.u3.ip6,
                                       src.src.u.tcp.port,
                                       src.dst.u.tcp.port,
                                       0);
            break;
        case IPPROTO_UDP:
            sk = sock_stat_lookup_udp6_exact(src.src.u3.ip6,
                                             src.dst.u3.ip6,
                                             src.src.u.udp.port,
                                             src.dst.u.tcp.port,
                                             0);
            break;
        case IPPROTO_UDPLITE:
            /* FIXME: impl. */
        default:
            break;
        }
        break;
    default:
        /* not supported for the others */
        break;
    }

    return sk;
}


