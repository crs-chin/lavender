/*
 * cactus_be.h cactus backend interface
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

#ifndef __CACTUS_BE_H
#define __CACTUS_BE_H

#include <stdarg.h>

#include "util.h"
#include "fw_table.h"

__BEGIN_DECLS

int cactus_be_init(void);

int cactus_be_send_verdict(fw_obj *fobj);

int cactus_be_send_info(int type, int len, char *info);
int cactus_be_send_printf(int type, const char *fmt, ...);

#define CACTUS_BE_MSG(fmt,args...)                  \
    cactus_be_send_printf(INFO_MSG, fmt, ##args)

#define CACTUS_BE_RATELIMIT_INTERVAL 10000

#define ___CACTUS_BE_MSG_RATELIMIT(rl,key,fmt,args...)                  \
    do{if(! __rate_limit(rl,key)) CACTUS_BE_MSG(fmt,##args);}while(0)

#define __CACTUS_BE_MSG_RATELIMIT(key,fmt,args...)      \
    {DEFINE_RATELIMIT(rl,CACTUS_BE_RATELIMIT_INTERVAL); \
        ___CACTUS_BE_MSG_RATELIMIT(&rl,key,fmt,##args);}

#define CACTUS_BE_MSG_RATELIMIT(fmt,args...)    \
    __CACTUS_BE_MSG_RATELIMIT(NULL,fmt,##args)

#define CACTUS_BE_MSG_RATELIMIT_PID(pid,fmt,args...)            \
    {char __key[20]; snprintf(__key, sizeof(__key), "%u", pid); \
        __CACTUS_BE_MSG_RATELIMIT(__key,fmt,##args);}

__END_DECLS

#endif  /* __CACTUS_BE_H */

