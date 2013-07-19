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


#include <string.h>
#include <malloc.h>

#include "util.h"
#include "branch.h"


int leaf_attach(leaf *l, branch *b)
{
    int i;
    _pad *p;
    _stem *s;
    _pads *pp;
    _stems *ss;

    leaf_for_each_pad(p,l)  {
        if(! p->stem)
            goto pad_found;
    }leaf_for_each_pad_end;

    if(! (pp = (_pads *)malloc(sizeof(*pp))))
        goto oom;

    memset(pp, 0, sizeof(*pp));
    __pads_for_each_pad(i, p, pp)  {
        p->leaf = l;
    }
    p = &pp->pad[0];
    list_append(&l->head, &pp->list);

 pad_found:

    branch_for_each_stem(s,b)  {
        if(! s->pad)
            goto stem_found;
    }branch_for_each_stem_end;

    if(! (ss = (_stems *)malloc(sizeof(*ss))))
        goto oom;

    memset(ss, 0, sizeof(*ss));
    __stems_for_each_stem(i, s, ss)  {
        s->branch = b;
    }
    s = &ss->stem[0];
    list_append(&b->head, &ss->list);

 stem_found:

    s->pad = p;
    s->branch->cnt++;
    p->stem = s;
    p->leaf->cnt++;
    return 0;

 oom:
    return -1;
}

