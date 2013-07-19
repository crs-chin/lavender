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

#ifndef __CACTUS_LOG_H
#define __CACTUS_LOG_H

#include <stdarg.h>

#include "util.h"
#include "msg_base.h"

__BEGIN_DECLS

int cactus_log_init(void);
void cactus_log_fini(void);

extern int log_ctl[NUM_LOG];
extern int log_mask[NUM_LVL];

/* NOTE: call after everything initialized! */
void cactus_log_set_ctl(int log, int enabled);
void cactus_log_flush(void);

int cactus_log(int lvl, int type, void *obj);
int cactus_log_printf(int lvl, const char *fmt, ...);

#ifndef NDEBUG
#define __LOG(lvl,fmt,args...)                                          \
    cactus_log_printf(LOG_##lvl, "[%s:%d]" fmt, __func__, __LINE__, ##args)
#else
#define __LOG(lvl,fmt,args...)                  \
    cactus_log_printf(LOG_##lvl, fmt, ##args)
#endif

#define LOG_DEBUG(fmt,args...) __LOG(DEBUG,fmt,##args)
#define LOG_INFO(fmt,args...)  __LOG(INFO,fmt,##args)
#define LOG_WARN(fmt,args...)  __LOG(WARN,fmt,##args)
#define LOG_EMERG(fmt,args...) __LOG(EMERG,fmt,##args)
#define LOG_ERROR(fmt,args...)  __LOG(ERROR,fmt,##args)
#define LOG_FATAL(fmt,args ...)  __LOG(FATAL,fmt,##args)

#define LOG_RTNL(msg)                           \
    cactus_log(LOG_INFO, LOG_RTNL, msg);

#define LOG_UEVENT(msg)                         \
    cactus_log(LOG_INFO, LOG_UEVENT, msg);

#define LOG_CONNTRACK(msg)                      \
    __LOG_CONNTRACK(msg,NULL)

typedef struct _conntrack_info conntrack_info;

struct _conntrack_info{
    void *ct;
    /**
     * fd_owner for this connection, auto lookup if set to NULL, set
     * to a empty list if no related fd_owner.
     */
    list *ls;
};

#define __LOG_CONNTRACK(msg,fos)                        \
    ({conntrack_info info = {.ct = msg, .ls = fos, };   \
        cactus_log(LOG_INFO, LOG_CONNTRACK, &info);})

__END_DECLS

#endif  /* __CACTUS_LOG_H */

