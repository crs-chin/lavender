/*
 * linxu_timerfd.S
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

#include <asm/unistd.h>
#include <machine/asm.h>
#include <sys/linux-syscalls.h>

#include "cust.h"

#if ! HAVE_SYS_TIMERFD_H

#if !defined(__NR_timerfd_create) || !defined(__NR_timerfd_settime) || !defined(__NR_timerfd_gettime)
#error Abort! timerfd syscalls not supported.
#endif

ENTRY(timerfd_create)
    .save   {r4, r7}
    stmfd   sp!, {r4, r7}
    ldr     r7, =__NR_timerfd_create
    swi     #0
    ldmfd   sp!, {r4, r7}
    movs    r0, r0
    bxpl    lr
    b       __set_syscall_errno
END(timerfd_create)


ENTRY(timerfd_settime)
    .save   {r4, r7}
    stmfd   sp!, {r4, r7}
    ldr     r7, =__NR_timerfd_settime
    swi     #0
    ldmfd   sp!, {r4, r7}
    movs    r0, r0
    bxpl    lr
    b       __set_syscall_errno
END(timerfd_settime)


ENTRY(timerfd_gettime)
    .save   {r4, r7}
    stmfd   sp!, {r4, r7}
    ldr     r7, =__NR_timerfd_gettime
    swi     #0
    ldmfd   sp!, {r4, r7}
    movs    r0, r0
    bxpl    lr
    b       __set_syscall_errno
END(timerfd_gettime)

#endif

#if ! HAVE_SYS_SIGNALFD_H

ENTRY(__signalfd)
    .save   {r4, r7}
    stmfd   sp!, {r4, r7}
#ifdef __NR_signalfd4
    ldr     r7, =__NR_signalfd4
#elif defined __NR_signalfd
    ldr     r7, =__NR_signalfd
#else
#error Abort! signalfd syscall not supported.
#endif
    swi     #0
    ldmfd   sp!, {r4, r7}
    movs    r0, r0
    bxpl    lr
    b       __set_syscall_errno
END(__signalfd)

#endif

#if ! HAVE_READLINKAT

#if !defined(__NR_readlinkat)
#error Abort! readlinkat syscall not supported.
#endif

ENTRY(readlinkat)
    .save   {r4, r7}
    stmfd   sp!, {r4, r7}
    ldr     r7, =__NR_readlinkat
    swi     #0
    ldmfd   sp!, {r4, r7}
    movs    r0, r0
    bxpl    lr
    b       __set_syscall_errno
END(readlinkat)

#endif

