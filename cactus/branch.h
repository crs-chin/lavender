/*
 * branch.h tree like branches
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

#ifndef __BRANCH_H
#define __BRANCH_H

#include <string.h>
#include <sys/types.h>

#include "util.h"

__BEGIN_DECLS

#ifndef BRANCH_SIZE
#define BRANCH_SIZE 4
#endif

/**
 * INTRO: A leaf can be attached and detached to a branch, and
 * branches can iterate all leaf embeded objects, a leaf can detach
 * itself from the branch, and iterate all branch embeded objects.
 * FIXME: look like a little too much mem over head.
 */

typedef struct _branch branch;
typedef struct _leaf leaf;
/* internal types */
typedef struct __stem _stem;
typedef struct __stems _stems;
typedef struct __pad _pad;
typedef struct __pads _pads;

struct __stem{
    _pad *pad;
    branch *branch;
};

struct __stems{
    _stem stem[BRANCH_SIZE];
    list list;
};

struct __pad{
    _stem *stem;
    leaf *leaf;
};

struct __pads{
    _pad pad[BRANCH_SIZE];
    list list;
};

struct _branch{
    list head;
    size_t cnt;
    _stems stem;
};

struct _leaf{
    list head;
    size_t cnt;
    _pads pad;
};


#define __stems_for_each_stem(i,iter,stems)                             \
    for(i = 0, iter = &(stems)->stem[0]; i < BRANCH_SIZE; i++, iter++)

#define __pads_for_each_pad(i,iter,pads)                                \
    for(i = 0, iter = &(pads)->pad[0]; i < BRANCH_SIZE; i++, iter++)


static inline void branch_init(branch *b)
{
    int i;
    _stem *s;

    memset(b, 0, sizeof(*b));
    list_init(&b->head);
    list_append(&b->head, &b->stem.list);
    __stems_for_each_stem(i, s, &b->stem)
        s->branch = b;
}

static inline void leaf_init(leaf *l)
{
    int i;
    _pad *p;

    memset(l, 0, sizeof(*l));
    list_init(&l->head);
    list_append(&l->head, &l->pad.list);
    __pads_for_each_pad(i, p, &l->pad)
        p->leaf = l;
}

#define branch_for_each_leaf(l,b)               \
    {int _i; _stems *_ss; _stem *_s;            \
    list_for_each_entry(_ss,&(b)->head,list)  { \
    __stems_for_each_stem(_i,_s,_ss)  {         \
    if(! _s->pad)  continue;                    \
    l = _s->pad->leaf;

#define branch_for_each_end }}}

#define branch_for_each_leaf_entry(iter,b,member)   \
    {leaf *_l;                                      \
    branch_for_each_leaf(_l,b)                      \
    iter = container_of(_l, typeof(*iter), member);

#define branch_for_each_entry_end branch_for_each_end}

#define leaf_for_each_branch(b,l)               \
    {int _i; _pads *_pp; _pad *_p;              \
    list_for_each_entry(_pp,&(l)->head,list)  { \
    __pads_for_each_pad(_i,_p,_pp)  {           \
    if(! _p->stem) continue;                    \
    b = _p->stem->branch;

#define leaf_for_each_end }}}

#define leaf_for_each_branch_entry(iter,l,member)   \
    {branch *_b;                                    \
    leaf_for_each_branch(_b,l)                      \
    iter = container_of(_b,typeof(*iter),member);

#define leaf_for_each_entry_end leaf_for_each_end}

#define branch_for_each_stem(s,b)               \
    {int _i; _stems *_ss;                       \
    list_for_each_entry(_ss,&(b)->head,list)  { \
    __stems_for_each_stem(_i,s,_ss)  {

#define branch_for_each_stem_attached(s,b)      \
    branch_for_each_stem(s,b)                   \
    if(! s->pad)  continue;

#define branch_for_each_stem_end }}}

#define leaf_for_each_pad(p,l)                  \
    {int _i; _pads *_pp;                        \
    list_for_each_entry(_pp,&(l)->head,list)  { \
    __pads_for_each_pad(_i,p,_pp)  {            \

#define leaf_for_each_pad_attached(p,l)         \
    leaf_for_each_pad(p,l)                      \
    if(! p->stem) continue;

#define leaf_for_each_pad_end }}}

#define __pad_detach(p)                             \
    do{(p)->stem->branch->cnt--;                    \
        (p)->stem->pad = NULL; (p)->stem = NULL;    \
    }while(0)

#define __stem_detach(s)                        \
    do{(s)->pad->leaf->cnt--;                   \
        (s)->pad->stem = NULL; (s)->pad = NULL; \
    }while(0)


#define leaf_detach(l,obj,member)                                       \
    do{_pad *_p;__label__ __out;                                        \
        leaf_for_each_pad_attached(_p,l)  {                             \
            if(obj == container_of(_p->stem->branch,typeof(*obj),member))  { \
                __pad_detach(_p);                                       \
                goto __out;}                                            \
        }leaf_for_each_pad_end;                                         \
    __out:;}while(0)


#define branch_release(b,obj,member)                                    \
    do{_stem *_s; __label__ __out;                                      \
        branch_for_each_stem_attached(_s,b)  {                          \
            if(obj == container_of(_s->pad->leaf,typeof(*obj),member))  { \
                __stem_detach(_s);                                      \
                goto __out;}                                            \
        }branch_for_each_stem_end;                                      \
    __out:;}while(0)

/**
 * detach all "branch"s refed the the leaf
 */
static inline void leaf_detach_all(leaf *l)
{
    _pad *p;

    if(l->cnt > 0)  {
        leaf_for_each_pad_attached(p, l)  {
            __pad_detach(p);
        }leaf_for_each_end;
        l->cnt = 0;
    }
}

static inline void leaf_free(leaf *l)
{
    _pads *pp, *n;

    leaf_detach_all(l);
    list_for_each_entry_safe(pp, n, &l->head, list)  {
        if(pp != &l->pad)
            free(pp);
    }
}

int leaf_attach(leaf *l, branch *b);


/**
 * release all "leaf"s attached
 */
static inline void branch_release_all(branch *b)
{
    _stem *s;

    if(b->cnt > 0)  {
        branch_for_each_stem_attached(s,b)  {
            __stem_detach(s);
        }branch_for_each_stem_end;
        b->cnt = 0;
    }
}

static inline void branch_free(branch *b)
{
    _stems *ss, *n;

    branch_release_all(b);
    list_for_each_entry_safe(ss, n, &b->head, list)  {
        if(ss != &b->stem)
            free(ss);
    }
}

__END_DECLS

#endif  /* ! __BRANCH_H */

