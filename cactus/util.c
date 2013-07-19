/*
 * Copyright (C) <2012>  Cross Chin <crs.chin@gmail.com>
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

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "util.h"
#include "cactus_log.h"

unsigned long djb2_hash(const unsigned char *str)
{
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

unsigned long sdbm_hash(const unsigned char *str)
{
    unsigned long hash = 0;
    int c;

    while ((c = *str++))
        hash = c + (hash << 6) + (hash << 16) - hash;

    return hash;
}

int mkpath(const char *path)
{
    struct stat st;
    char _path[strlen(path) + 1];
    char *p, *slash = _path;

    if(! access(path, W_OK))  {
        if(! stat(path, &st))  {
            if(S_ISDIR(st.st_mode))
                return 0;
            LOG_ERROR("directory not a a directory:%s", path);
            return -1;
        }
        LOG_ERROR("fail to stat path %s:%d(%s)", errno, strerror(errno));
        return -1;
    }

    strcpy(_path, path);
    if(*slash == '/')
        slash++;
    p = NULL;
    for(;;)  {
        if(! slash)
            return 0;
        if(p)
            *p = '/';
        if((slash = strchr(slash, '/')))  {
            p = slash++;
            *p = '\0';
        }else  {
            slash = NULL;
        }
        if(! stat(_path, &st))  {
            if(! S_ISDIR(st.st_mode))  {
                LOG_ERROR("invalid directory path:%s", _path);
                return -1;
            }
            continue;
        }
        if(mkdir(_path, 0700))  {
            LOG_ERROR("fail to mkdir directory \"%s\":%d(%s)", _path, errno, strerror(errno));
            return -1;
        }
    }
    return -1;
}

int __rate_limit(rate_limit *rl, const char *key)
{
    struct timespec ts;
    int limited = 0;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    pthread_mutex_lock(&rl->lock);
    if(! key)
        key = "";
    if(! strcmp(key, rl->key))  {
        if(ts_cmp(&ts, &rl->ts) < 0)
            limited = 1;
        else  {
            ts_add(&ts, rl->rate);
            rl->ts = ts;
        }
    }else  {
        strcpy(rl->key, key);
        ts_add(&ts, rl->rate);
        rl->ts = ts;
    }
    pthread_mutex_unlock(&rl->lock);
    return limited;
}

#if ! HAVE_GETLINE
#define MIN_BUF_SZ 100

ssize_t __getdelim(char **line, size_t *n, int delim, FILE *fp)
{
    char *buf, *p;
    size_t i, sz;
    int c;

    if(! line || ! n || ! fp)  {
        errno = EINVAL;
        return -1;
    }

    buf = *line;
    sz = *n;
    if(! buf || ! sz)  {
        if(! (buf = malloc(MIN_BUF_SZ)))  {
            errno = ENOMEM;
            return -1;
        }
        sz = MIN_BUF_SZ;
    }

    for(p = buf, i = 0;;)  {
        c = fgetc(fp);
        if(c == delim || c == EOF)
            break;
        p[i++] = c;
        if(i == sz)  {
            if(! (p = realloc(buf, sz + MIN_BUF_SZ)))  {
                errno = ENOMEM;
                break;
            }
            sz += MIN_BUF_SZ;
            buf = p;
        }
    }

    *line = buf;
    *n = sz;
    buf[i] = '\0';
    if(c == EOF || ! p)
        return -1;
    /* delimter included */
    return i + 1;
}
#endif

#if ! HAVE_PIPE2
static inline int __change_flags(int fd, int flags)
{
    int f1, f2, err = 0;

    f2 = f1 = fcntl(fd, F_GETFL, 0);
    if(flags & O_NONBLOCK)
        f1 |= O_NONBLOCK;
    else
        f1 &= ~O_NONBLOCK;
    if(f1 != f2)
        err = fcntl(fd, F_SETFL, f1);
    if(! err)  {
        f2 = f1 = fcntl(fd, F_GETFD, 0);
        if(flags & O_CLOEXEC)
            f1 |= FD_CLOEXEC;
        else
            f1 &= ~FD_CLOEXEC;
        if(f1 != f2)
            err = fcntl(fd, F_SETFD, f1);
    }
    return err;
}

int pipe2(int fd[2], int flags)
{
    int err = pipe(fd);

    if(! err)  {
        err = __change_flags(fd[0], flags);
        if(! err)
            err = __change_flags(fd[1], flags);
        if(err)  {
            close(fd[0]);
            close(fd[1]);
        }
    }
    return err;
}
#endif
