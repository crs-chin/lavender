/*
 * gardenia.c
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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>

#include "util.h"
#include "gardenia.h"


typedef struct _log_entry log_entry;

struct _log_entry{
    list list;
    int idx;
    size_t size;
    char *name;
};

struct _gardenia{
    pthread_mutex_t lock;
    char *path;
    char *prefix;

    ssize_t storage_limit;
    ssize_t rotate_size;

    list logs;
    size_t count;

    size_t size;
    log_entry *cur;
    FILE *fp;
};


static int check_idx(const char *postfix)
{
    const char *p = postfix;

    if(! *p)
        return 0;

    if(*p++ != '.')
        return -1;

    do{
        if(*p < '0' || *p > '9')
            return -1;
    }while(* ++p);

    return atoi(postfix + 1);
}

static log_entry *init_log_entry(gardenia *g, const char *name, int prefix)
{
    struct stat st;
    log_entry *en;
    char *path;
    int idx = check_idx(name + prefix);

    if(idx < 0)
        return NULL;

    if(asprintf(&path, "%s/%s", g->path, name) < 0)
        return NULL;

    if(stat(path, &st) < 0)
        memset(&st, 0, sizeof(st));

    if(! (en = new_instance(log_entry)))  {
        free(path);
        return NULL;
    }

    en->idx = idx;
    en->size = st.st_size;
    en->name = path;
    list_init(&en->list);
    return en;
}


static void log_entry_add(gardenia *g, log_entry *en)
{
    log_entry *e, *n;

    g->count++;
    list_for_each_entry_safe(e, n, &g->logs, list)  {
        if(en->idx <= e->idx)  {
            list_append(&e->list, &en->list);
            return;
        }
    }
    list_append(&g->logs, &en->list);
}

static int trim(gardenia *g)
{
    log_entry *en;
    int res = -1;

    if(list_empty(&g->logs))
        return 0;

    en = list_entry(g->logs.l_prv, log_entry, list);
    if(! (res = unlink(en->name)))  {
        PR_INFO("%s %d trimmed", en->name, en->size);
        g->size -= en->size;
        list_delete(&en->list);
        free(en->name);
        free(en);
    }
    return res;
}


static int rotate_log_entry(gardenia *g, log_entry *en)
{
    char *name;

    if(en == g->cur && g->fp)  {
        fclose(g->fp);
        g->cur = NULL;
        g->fp = NULL;
    }

    if(asprintf(&name, "%s/%s.log.%d", g->path, g->prefix, en->idx + 1) < 0)
        return -1;

    if(rename(en->name, name) < 0)  {
        free(name);
        return -1;
    }

    free(en->name);
    en->name = name;
    en->idx += 1;
    return 0;
}

static int init_log_head(gardenia *g)
{
    log_entry *en;
    char *f;

    if(g->cur)
        g->cur = NULL;
    if(g->fp)
        g->fp = NULL;

    if(asprintf(&f, "%s.log", g->prefix) < 0)
        return -1;

    if(! (en = init_log_entry(g, f, strlen(f))))  {
        free(f);
        return -1;
    }

    free(f);
    log_entry_add(g, en);

    g->cur = en;
    if(! (g->fp = fopen(en->name, "a")))
        return -1;
    return 0;
}

static int rotate(gardenia *g)
{
    log_entry *en;

    if(g->fp)  {
        fclose(g->fp);
        g->fp = NULL;
        g->cur = NULL;
    }

    list_for_each_entry_prev(en, &g->logs, list)  {
        if(rotate_log_entry(g, en))  {
            PR_ERROR("fail to retate log entry\n");
            return -1;
        }
    }

    return init_log_head(g);
}

static int gardenia_open(gardenia *g)
{
    log_entry *en;
    size_t s = 0;

    while(g->storage_limit > 0 && g->size >= (size_t)g->storage_limit)  {
        if(trim(g) || rotate(g))
            return -1;
    }

    if(! list_empty(&g->logs))  {
        en = list_entry(g->logs.l_nxt, log_entry, list);
        s = en->size;
    }

    if(g->rotate_size > 0 && s >= (size_t)g->rotate_size && rotate(g))
        return -1;

    if(list_empty(&g->logs))  {
        if(init_log_head(g))
            return -1;
    }else  {
        g->cur = list_entry(g->logs.l_nxt, log_entry, list);
        if(! (g->fp = fopen(g->cur->name, "a")))
            return -1;
    }
    return 0;
}

static int gardenia_init(gardenia *g)
{
    DIR *dir;
    struct dirent *ent;
    char *base;
    ssize_t len = asprintf(&base, "%s.log", g->prefix);
    log_entry *log;
    int idx;

    if(len < 0)
        return -1;

    if(mkpath(g->path))  {
        free(base);
        return -1;
    }

    if(! (dir = opendir(g->path)))  {
        free(base);
        return -1;
    }

    for(g->size = 0, ent = readdir(dir); ent; ent = readdir(dir))  {
        if(ent->d_type != DT_REG)
            continue;
        if(! strncmp(ent->d_name, base, len))  {
            log = init_log_entry(g, ent->d_name, len);
            if(log)  {
                log_entry_add(g, log);
                g->size += log->size;
            }
        }
    }
    free(base);
    closedir(dir);

    return gardenia_open(g);
}


static void __gardenia_destroy(gardenia *g)
{
    log_entry *en, *n;

    if(g->path)
        free(g->path);
    if(g->prefix)
        free(g->prefix);
    if(g->fp)
        fclose(g->fp);

    list_for_each_entry_safe(en, n, &g->logs, list)  {
        list_delete(&en->list);
        if(en->name)
            free(en->name);
        free(en);
    }
}

gardenia *gardenia_create(const char *path,
                          const char *prefix,
                          ssize_t storage_limit,
                          ssize_t rotate_size)
{
    gardenia g, *ret;

    if(! path)
        path = "./";
    if(! prefix)
        prefix = "gardenia";
    if(storage_limit >= 0 && storage_limit < MIN_STORAGE_SIZE)
        storage_limit = MIN_STORAGE_SIZE;
    if(rotate_size >= 0 && rotate_size < MIN_ROTATE_SIZE)
        rotate_size = MIN_ROTATE_SIZE;

    pthread_mutex_init(&g.lock, NULL);
    g.path = strdup(path);
    g.prefix = strdup(prefix);
    g.storage_limit = storage_limit;
    g.rotate_size = rotate_size;
    list_init(&g.logs);
    g.count = 0;
    g.size = 0;
    g.cur = NULL;
    g.fp = NULL;

    if(! g.path || ! g.prefix || gardenia_init(&g))  {
        __gardenia_destroy(&g);
        return NULL;
    }

    if(! (ret = objdup(&g)))
        __gardenia_destroy(&g);
    list_assign(&ret->logs, &g.logs);
    return ret;
}


static int check_rotate(gardenia *g)
{
    while(g->storage_limit > 0 && g->size >= (size_t)g->storage_limit)  {
        if(trim(g))
            return -1;
    }

    if(g->rotate_size > 0 && (size_t)g->rotate_size <= g->cur->size)  {
        PR_DEBUG("rotate now");
        if(rotate(g))  {
            PR_WARN("fail to rotate log");
            return -1;
        }
    }
    return 0;
}

int gardenia_print(gardenia *g, const char *fmt, ...)
{
    va_list ap;
    int res = -1;

    if(! g || ! fmt)
        return -1;

    pthread_mutex_lock(&g->lock);
    if(g->fp)  {
        va_start(ap, fmt);
        res = vfprintf(g->fp, fmt, ap);
        va_end(ap);

        if(res > 0)  {
            g->cur->size += res;
            g->size += res;
            check_rotate(g);
        }else  {
            PR_ERROR("fail to print log");
        }
    }
    pthread_mutex_unlock(&g->lock);
    return res;
}

int gardenia_write(gardenia *g, const void *blob, size_t sz)
{
    va_list ap;
    int res = -1;

    if(! g || ! blob || ! sz)
        return -1;

    pthread_mutex_lock(&g->lock);
    if(g->fp)  {
        res = fwrite(blob, sz, 1, g->fp);
        if(res > 0)  {
            g->cur->size += sz;
            g->size += sz;
            check_rotate(g);
        }
    }
    pthread_mutex_unlock(&g->lock);
    return res > 0 ? (int)sz : -1;
}

int gardenia_purge(gardenia *g)
{
    log_entry *en, *n;

    if(! g)
        return -1;

    list_for_each_entry_safe_prev(en, n, &g->logs, list)  {
        if(unlink(en->name))
            return -1;
        if(en == g->cur)  {
            g->cur = NULL;
            if(g->fp)  {
                fclose(g->fp);
                g->fp = NULL;
            }
        }
        list_delete(&en->list);
        g->size -= en->size;
        free(en->name);
        free(en);
    }
    return 0;
}


/**
 * flush all logs in the cache
 */
void gardenia_flush(gardenia *g)
{
    if(g)  {
        pthread_mutex_lock(&g->lock);
        if(g->fp)
            fflush(g->fp);
        pthread_mutex_unlock(&g->lock);
    }
}

void gardenia_destroy(gardenia *g)
{
    __gardenia_destroy(g);
    free(g);
}

