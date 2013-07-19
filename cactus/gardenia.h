/*
 * gardenia.h log subsystem
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

#ifndef __GARDENIA_H
#define __GARDENIA_H

#include <stdarg.h>
#include <sys/types.h>

__BEGIN_DECLS

#define MIN_STORAGE_SIZE (10 * 1024 * 1024)
#define MIN_ROTATE_SIZE (1024 * 1024)

typedef struct _gardenia gardenia;

gardenia *gardenia_create(const char *path,
                          const char *prefix,
                          ssize_t storage_limit,
                          ssize_t rotate_size);

int gardenia_print(gardenia *g, const char *fmt, ...);
int gardenia_write(gardenia *g, const void *blob, size_t sz);

/**
 * purge all gardenia log files
 */
int gardenia_purge(gardenia *g);

/**
 * flush all logs in the cache
 */
void gardenia_flush(gardenia *g);

void gardenia_destroy(gardenia *g);

__END_DECLS

#endif  /* __GARDENIA_H */

