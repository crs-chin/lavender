/*
 * cust.h
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

#ifndef __CUST_H
#define __CUST_H 

#ifdef ANDROID_CHANGES

#define BASE_DIR "/data/" PACKAGE_NAME "/"

/* Cactus log directory */
#define CONFIG_LOG_FILE_PATH BASE_DIR "log/"

/* Cactus log file prefix */
#define CONFIG_LOG_FILE_PREFIX PACKAGE_NAME

/* Cactus pid lock file path */
#define CONFIG_PID_LOCK BASE_DIR PACKAGE_NAME ".pid"

/* Cactus default rule list path */
#define CONFIG_RULE_DIR BASE_DIR "rules/"

/* Cactus default rule file name */
#define CONFIG_RULE_FILE "rule.list"

/* Cactus default stat file dir */
#define CONFIG_STAT_DIR BASE_DIR

/* Cactus default state file name */
#define CONFIG_STAT_FILE PACKAGE_NAME ".stat"

/* Name of package */
#define PACKAGE "lavender"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "crs.chin@gmail.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "lavender"

/* Version number of package */
#define VERSION "0.2.0"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "lavender " VERSION

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION VERSION

/* all c code */
#ifndef __THROW
#define __THROW
#endif

/* android got different names */
#define be64toh betoh64

#else  /* ! ANDROID_CHANGES */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#endif

#endif  /* ! __CUST_H */
