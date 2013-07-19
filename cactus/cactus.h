/*
 * cactus.h Lavender Runtime Library
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

#ifndef __CACTUS_H
#define __CACTUS_H

#include <netinet/in.h>

#include "util.h"
#include "kconf.h"
#include "ginkgo.h"
#include "ipclite.h"
#include "rpclite.h"
#include "fw_table.h"
#include "gardenia.h"
#include "jhash.h"
#include "md5.h"
#include "msg_base.h"
#include "msg.h"
#include "nl.h"
#include "nfct.h"
#include "nfq.h"
#include "rtnl.h"
#include "uevent.h"
#include "fd_lookup.h"
#include "sock_stat.h"
#include "timer.h"
#include "core.h"
#include "cactus_log.h"
#include "cactus_be.h"

__BEGIN_DECLS

static inline int cactus_startup(void)
{
    if(! core_init())
        return core_start();
    return -1;
}

__END_DECLS

#endif  /* __CACTUS_H */

