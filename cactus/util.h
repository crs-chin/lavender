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

#ifndef __UTIL_H
#define __UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <malloc.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <fcntl.h>

#include "cust.h"

#define arraysize(a)  (sizeof(a)/sizeof(a[0]))

#define offset_of(type,member)                  \
    ((size_t)&((type *)0)->member)

#define container_of(ptr,type,member)           \
    ((type *)((unsigned char *)(ptr) - offset_of(type,member)))

#define new_instance(type) (type *)malloc(sizeof(type))
#define new_instance_ex(type,payload) (type *)malloc(sizeof(type) + payload)

#define instantiate(var) (var = new_instance(typeof(*var)))
#define instantiate_ex(var,payload) (var = new_instance_ex(typeof(*var),payload))

#define free_if(ptr) do{if(ptr) free(ptr);}while(0)

#define IP_FMT "%u.%u.%u.%u"
#define __IP_ARG(ip,idx) ((__u8 *)&(ip))[idx]
#define IP_ARG(ip) __IP_ARG(ip,0),__IP_ARG(ip,1),__IP_ARG(ip,2),__IP_ARG(ip,3)

#define build_fail_on(exp) ((void)sizeof(char[1 - 2 * (!!(exp))]))

#ifndef MAX
 #define MAX(a,b)  ({typeof(a) _a = a; typeof(b) _b = b; ((_a > _b) ? _a : _b);})
#endif

#ifndef MIN
 #define MIN(a,b)  ({typeof(a) _a = a; typeof(b) _b = b; ((_a > _b) ? _b : _a);})
#endif

#define BZERO(o) bzero(o,sizeof(*o))

#define ___stringify(x...) #x
#define __stringify(x...) ___stringify(x)

#define DEFINE_RATELIMIT(name,interval)         \
    static rate_limit name = {                  \
        .lock = PTHREAD_MUTEX_INITIALIZER,      \
        .ts = {0, 0},                           \
        .rate = interval,                       \
        .key = "",                              \
    }

#ifndef NDEBUG
 #define PR_ERROR(fmt,args...) LOGERROR(fmt,##args);
 #define PR_WARN(fmt,args...) LOGWARN(fmt,##args);
 #define PR_INFO(fmt,args...) LOGINFO(fmt,##args);
 #define PR_DEBUG(fmt,args...) LOGDEBUG(fmt,##args);

 #ifdef ANDROID_CHANGES
  #define LOG_TAG "LAVENDER"
  #include <utils/log.h>

  #define LOGERROR(fmt,args...) ALOGE(fmt, ##args)
  #define LOGWARN(fmt,args...) ALOGW(fmt, ##args)
  #define LOGINFO(fmt,args...) ALOGI(fmt, ##args)
  #define LOGDEBUG(fmt,args...) ALOGD(fmt, ##args)
 #else
  #define LOGERROR(fmt,args...) fprintf(stderr, "[ERROR]" fmt "\n", ##args)
  #define LOGWARN(fmt,args...) fprintf(stderr, "[WARN]" fmt "\n", ##args)
  #define LOGINFO(fmt,args...) fprintf(stdout, "[INFO]" fmt "\n", ##args)
  #define LOGDEBUG(fmt,args...) fprintf(stdout, "[DEBUG]" fmt "\n", ##args)
 #endif
#else
 #define PR_ERROR(fmt,args...) do{}while(0)
 #define PR_WARN(fmt,args...) do{}while(0)
 #define PR_INFO(fmt,args...) do{}while(0)
 #define PR_DEBUG(fmt,args...) do{}while(0)

 #define LOGERROR(fmt,args...) do{}while(0)
 #define LOGWARN(fmt,args...) do{}while(0)
 #define LOGINFO(fmt,args...) do{}while(0)
 #define LOGDEBUG(fmt,args...) do{}while(0)
#endif

typedef struct _list list;
typedef struct _queue queue;
typedef struct _hlist hlist;
typedef struct _hlist_head hlist_head;
typedef struct _htable htable;

typedef unsigned long (*htable_hash)(void *key);
typedef int (*htable_cmp)(hlist *h, void *key);
typedef void (*htable_free)(hlist *h);

struct _list{
    list *l_nxt;
    list *l_prv;
};


struct _queue{
    pthread_mutex_t lock;
    pthread_cond_t cond;
    size_t count;
    list queue;
};

struct _hlist{
    hlist *h_nxt;
    hlist **h_pprv;
};


struct _hlist_head{
    hlist *h_head;
};

struct _htable{
    size_t h_siz;
    size_t h_cnt;
    htable_hash h_hsh;
    htable_cmp h_cmp;
    htable_free h_fre;
    hlist_head h_arr[0];
};


#define LIST_HEAD_INIT(name)  {&(name), &(name)}

static inline void list_init(list *l)
{
    l->l_nxt = l;
    l->l_prv = l;
}

static inline void list_append(list *h, list *elem)
{
    elem->l_prv = h->l_prv;
    elem->l_nxt = h;
    elem->l_prv->l_nxt = elem;
    h->l_prv = elem;
}

static inline void list_insert(list *l, list *elem)
{
    elem->l_prv = l;
    elem->l_nxt = l->l_nxt;
    elem->l_nxt->l_prv = elem;
    l->l_nxt = elem;
}

static inline void list_delete(list *l)
{
    l->l_nxt->l_prv = l->l_prv;
    l->l_prv->l_nxt = l->l_nxt;
    list_init(l);
}

static inline int list_empty(list *h)
{
    return (h->l_nxt == h);
}

static inline void list_assign(list *to, list *from)
{
    if(! list_empty(from))  {
        to->l_nxt = from->l_nxt;
        to->l_prv = from->l_prv;
        from->l_nxt->l_prv = to;
        from->l_prv->l_nxt = to;
        list_init(from);
    }else  {
        list_init(to);
    }
}

static inline void list_add(list *to, list *from)
{
    if(! list_empty(from))  {
        to->l_prv->l_nxt = from->l_nxt;
        from->l_nxt->l_prv = to->l_prv;

        to->l_prv = from->l_prv;
        from->l_prv->l_nxt = to;
    }
}

#define list_entry(ptr,type,member)       \
    container_of((ptr),type,member)

#define list_for_each(iter,head)                                    \
    for(iter = (head)->l_nxt; iter != (head); iter = iter->l_nxt)

#define list_for_each_safe(iter,n,head)         \
    for(iter = (head)->l_nxt, n = iter->l_nxt;  \
        iter != (head);                         \
        iter = n, n = iter->l_nxt)

#define list_for_each_entry(iter,head,member)                       \
    for(iter = list_entry((head)->l_nxt,typeof(*iter),member);      \
        &(iter)->member != (head);                                  \
        iter = list_entry(iter->member.l_nxt,typeof(*iter),member))

#define list_for_each_entry_safe(iter,n,head,member)                    \
    for(iter = list_entry((head)->l_nxt,typeof(*iter),member),          \
            n = list_entry(iter->member.l_nxt,typeof(*iter),member);    \
        &(iter)->member != (head);                                      \
        iter = n, n = list_entry(iter->member.l_nxt,typeof(*iter),member))

#define list_for_each_prev(iter,head)           \
    for(iter = (head)->l_prv; iter != (head); iter = iter->l_prv)

#define list_for_each_prev_safe(iter,n,head)    \
    for(iter = (head)->l_prv, n = iter->l_prv;  \
        iter != (head);                         \
        iter = n, n = iter->l_prv)

#define list_for_each_entry_prev(iter,head,member)                  \
    for(iter = list_entry((head)->l_prv,typeof(*iter),member);      \
        &(iter)->member != (head);                                  \
        iter = list_entry(iter->member.l_prv,typeof(*iter),member))

#define list_for_each_entry_safe_prev(iter,n,head,member)               \
    for(iter = list_entry((head)->l_prv,typeof(*iter),member),          \
            n = list_entry(iter->member.l_prv,typeof(*iter),member);    \
        &(iter)->member != (head);                                      \
        iter = n, n = list_entry(iter->member.l_prv,typeof(*iter),member))

#define list_for_each_entry_continue(iter,head,member)                  \
    for(iter = list_entry((iter)->member.l_nxt,typeof(*iter),member);   \
        &(iter)->member != (head);                                      \
        iter = list_entry((iter)->member.l_nxt,typeof(*iter),member))

#define list_for_each_entry_prev_continue(iter,head,member)             \
    for(iter = list_entry((iter)->member.l_prv,typeof(*iter),member);   \
        &(iter)->member != (head);                                      \
        iter = list_entry(iter->member.l_prv,typeof(*iter),member))

static void queue_init(queue *q)
{
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
    q->count = 0;
    list_init(&q->queue);
}


static void queue_lock(queue *q)
{
    pthread_mutex_lock(&q->lock);
}

static void queue_unlock(queue *q)
{
    pthread_mutex_unlock(&q->lock);
}


static void __queue_wait(queue *q)
{
    pthread_cond_wait(&q->cond, &q->lock);
}

static void __queue_wakeup(queue *q)
{
    pthread_cond_broadcast(&q->cond);
}

static void __enqueue(queue *q, list *l)
{
    list_append(&q->queue, l);
}

static list *__dequeue(queue *q)
{
    list *l = NULL;

    if(! list_empty(&q->queue))  {
        l = q->queue.l_nxt;
        list_delete(q->queue.l_nxt);
    }
    return l;
}

static void enqueue(queue *q, list *l)
{
    queue_lock(q);
    list_append(&q->queue, l);
    queue_unlock(q);
}

static list *dequeue(queue *q)
{
    list *l;

    queue_lock(q);
    l = __dequeue(q);
    queue_unlock(q);
    return l;
}

static void enqueue_wakeup(queue *q, list *l)
{
    queue_lock(q);
    list_append(&q->queue, l);
    __queue_wakeup(q);
    queue_unlock(q);
}


static list *dequeue_wakeup(queue *q)
{
    list *l;

    queue_lock(q);
    if((l = __dequeue(q)))
       __queue_wakeup(q);
    queue_unlock(q);
    return l;
}


#define queue_for_each(iter,q)                  \
    list_for_each(iter,&(q)->queue)

#define queue_for_each_entry(iter,q,member)         \
    list_for_each_entry(iter,&(q)->queue,member)

#define queue_for_each_entry_safe(iter,n,q,member)  \
    list_for_each_entry_safe(iter,n,&(q)->queue,member)


static inline void *memdup(const void *src, size_t len)
{
    void *dest = malloc(len);

    if(dest)
        memcpy(dest, src, len);
    return dest;
}

#define objdup(o)                               \
    ({typeof(o) _o = (typeof(o))memdup((const void *)o, sizeof(*(o))); _o;})

#define __WAIT_ON(cond,lock,exp)                \
    do{ pthread_cond_wait(cond, lock);         \
        if(exp) break; }while(1)

#define __WAKEUP(cond)                          \
    pthread_cond_broadcast(cond)


static inline void hlist_init(hlist *h)
{
    h->h_nxt = NULL;
    h->h_pprv = NULL;
}

static inline int hlist_hashed(hlist *h)
{
    return !! h->h_pprv;
}

static inline void hlist_head_init(hlist_head *h)
{
    h->h_head = NULL;
}

static inline void hlist_prepend(hlist_head *h, hlist *item)
{
    item->h_nxt = h->h_head;
    item->h_pprv = &h->h_head;
    h->h_head = item;
    if(item->h_nxt)
        item->h_nxt->h_pprv = &item->h_nxt;
}


static inline void hlist_insert(hlist *h, hlist *item)
{
    item->h_nxt = h->h_nxt;
    item->h_pprv = &h->h_nxt;
    h->h_nxt = item;
    if(item->h_nxt)
        item->h_nxt->h_pprv = &item->h_nxt;
}


static inline void hlist_delete(hlist *item)
{
    *item->h_pprv = item->h_nxt;
    if(item->h_nxt)
        item->h_nxt->h_pprv = item->h_pprv;
    item->h_nxt = NULL;
    item->h_pprv = NULL;
}


#define hlist_entry(ptr,type,member)            \
    container_of((ptr),type,member)

#define hlist_for_each(iter,head)               \
    for(iter = (head)->h_head; iter; iter = iter->h_nxt)

#define hlist_for_each_safe(pos, n, head)                       \
    for (pos = (head)->h_head; pos && ({ n = pos->h_nxt; 1; });   \
         pos = n)

#define hlist_for_each_entry(iter,pos,head,member)                      \
    for(pos = (head)->h_head;                                           \
        pos && ({ iter = hlist_entry(pos,typeof(*iter),member); 1;});   \
        pos = pos->h_nxt)

#define hlist_for_each_entry_safe(tpos,pos,n,head,member)               \
    for (pos = (head)->h_head;                                          \
         pos && ({ n = pos->h_nxt; 1; }) &&                             \
             ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;});   \
         pos = n)

static inline size_t htable_size(size_t sz)
{
    return (sizeof(htable) + sz * sizeof(hlist_head));
}

static inline void htable_init(htable *h,
                               size_t sz,
                               htable_hash hash,
                               htable_cmp cmp,
                               htable_free free)
{
    h->h_siz = sz;
    h->h_cnt = 0;
    h->h_hsh = hash;
    h->h_cmp = cmp;
    h->h_fre = free;
    memset((void *)h->h_arr, 0, sz * sizeof(hlist_head));
}


static inline unsigned long __htable_hash(htable *h, void *key)
{
    return (h->h_hsh(key) % h->h_siz);
}


static inline hlist_head *htable_find_head(htable *h, void *key)
{
    return &(h->h_arr[__htable_hash(h, key)]);
}


static inline hlist *htable_find_node(htable *h, void *key)
{
    hlist *iter = NULL;
    hlist_head *head = htable_find_head(h, key);

    hlist_for_each(iter,head)  {
        if(! h->h_cmp(iter, key))
            break;
    }
    return iter;
}

#define htable_find_entry(htable,key,type,member)   \
    ({ typeof(type) *val = NULL;                    \
    hlist *item = htable_find_node(htable,key);     \
    if(item)  val = hlist_entry(item,type,member); val; })

#define htable_for_each_head(i,head,htable)     \
    for(i = 0, head = &(htable)->h_arr[0];      \
        i < (htable)->h_siz;                    \
        head = &(htable)->h_arr[i++])

/* no duplicating check */
static inline void htable_insert(htable *h, void *key, hlist *item)
{
    hlist_head *head = htable_find_head(h, key);
    hlist_prepend(head, item);
    h->h_cnt++;
}


static inline hlist *__htable_delete(htable *h, void *key)
{
    hlist *node = htable_find_node(h, key);

    if(node)  {
        h->h_cnt--;
        hlist_delete(node);
    }
    return node;
}


static inline void htable_delete(htable *h, void *key)
{
    hlist *node = __htable_delete(h, key);
    if(node)
        h->h_fre(node);
}


static inline void htable_destroy(htable *h)
{
    hlist *iter;
    size_t i;

    for(i = 0; i < h->h_siz; i++)  {
        hlist_for_each(iter, &(h->h_arr[i]))  {
            h->h_fre(iter);
        }
    }
    h->h_cnt = 0;
}

/* famous string hash functions */
unsigned long djb2_hash(const unsigned char *str);
unsigned long sdbm_hash(const unsigned char *str);

static inline ssize_t
file_read(const char *path, char *buf, size_t sz)
{
    int fd = open(path, O_RDONLY);
    ssize_t ret = -1;

    if(fd >= 0)  {
        ret = read(fd, buf, sz);
        close(fd);
    }else  {
        PR_WARN("failed to open \"%s\" for reading:%d(%s)",
                path ? : "<NULL>", errno, strerror(errno));
    }
    return ret;
}

static inline int
file_read_int(const char *path, int *val)
{
    char buf[50];
    ssize_t ret = file_read(path, buf, sizeof(buf) - 1);

    if(ret > 0)  {
        buf[ret] = '\0';
        *val = atoi(buf);
        return 0;
    }
    return -1;
}

static inline ssize_t
file_write(const char *path, const char *val, ssize_t sz)
{
    int fd = open(path, O_WRONLY);
    int ret = -1;

    if(fd >= 0)  {
        ret = write(fd, val, (sz < 0) ? strlen(val) : (size_t)sz);
        close(fd);
    }else  {
        PR_WARN("failed to open \"%s\" for writing:%d(%s)",
                path ? : "<NULL>", errno, strerror(errno));
    }
    return ret;
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

static inline void ts_add(struct timespec *ts, unsigned int val)
{
    ts->tv_sec += val / 1000;
    ts->tv_nsec += (val % 1000) * 1000000;
    if(ts->tv_nsec > 1000000000)  {
        ts->tv_nsec -= 1000000000;
        ts->tv_sec++;
    }
}

int mkpath(const char *path);


typedef struct _rate_limit rate_limit;

struct _rate_limit{
    pthread_mutex_t lock;
    struct timespec ts;
    unsigned int rate;
    char key[20];
};

/* non-zero returned if limited */
int __rate_limit(rate_limit *rl, const char *key);

#if ! HAVE_GETLINE
#include <stdio.h>

ssize_t __getdelim(char **line, size_t *sz, int delim, FILE *fp);

static inline ssize_t getline(char **line, size_t *sz, FILE *fp)
{
    return __getdelim(line, sz, '\n', fp);
}

#endif

#if ! HAVE_READLINKAT
int readlinkat(int dirfd, const char *pathname,
               char *buf, size_t bufsiz);
#endif

#if ! HAVE_PIPE2
int pipe2(int fd[2], int flags);
#endif

#ifdef ANDROID_CHANGES
/* some data structures not defined */
enum  {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING   /* now a valid state */
};

/* not defined on android */
enum  {
    IPPROTO_UDPLITE = 136, /* UDP-Lite protocol.  */
#define IPPROTO_UDPLITE		IPPROTO_UDPLITE
};

/* android device doesn't need too big hash tables */
#define FW_TABLE_HASH_SIZE

#define INIT_CONN_HASH_SIZE (1024 * 2)
#define INIT_PROG_HASH_SIZE (256)
#define INIT_IDENT_HASH_SIZE (1024)
#define INIT_PROC_HASH_SIZE (1024)
#define INIT_USER_HASH_SIZE INIT_IDENT_HASH_SIZE

#endif  /* ! ANDROID_CHANGES */

#endif  /* __UTIL_H */

