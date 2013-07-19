/*
 * kconf.h dynamic kenrel feature detect
 * Copyright (C) 2013  Crs Chin <crs.chin@gmail.com>
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

#ifndef __KCONF_H
#define __KCONF_H

__BEGIN_DECLS

/**
 * strict mode, must have the required defined
 */
#define KCONF_F_STRICT 1

int kconf_init_check(int flags);

#define KCONF_U 0               /* undefined */
#define KCONF_N 1               /* explicit false */
#define KCONF_Y 2               /* explicit true */
#define KCONF_M 3               /* explicit module */

int kconf_get(const char *conf);

__END_DECLS

#endif  /* ! __KCONF_H */

