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

struct _list{
    list *l_nxt;
    list *l_prv;
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

static inline void *memdup(const void *src, size_t len)
{
    void *dest = malloc(len);

    if(dest)
        memcpy(dest, src, len);
    return dest;
}

#define objdup(o)                               \
    ({typeof(o) _o = (typeof(o))memdup((const void *)o, sizeof(*(o))); _o;})

#endif  /* __UTIL_H */

