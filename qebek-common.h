/*
 * 
 *
 * Copyright (C) 2009 Chengyu Song
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#ifndef QEBEK_COMMON_H
#define QEBEK_COMMON_H
#include "cpu.h"

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef VOID
#define VOID void
#endif

typedef void *PVOID;

#ifndef CONST
#define CONST const
#endif

typedef unsigned char BOOLEAN, bool;
typedef target_ulong ULONG;
typedef target_ulong HANDLE;
typedef unsigned short USHORT;

#ifndef False
#define False 0
#endif

#ifndef True
#define True 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

bool qebek_read_ulong(CPUX86State *env, target_ulong address, target_ulong *value);
bool qebek_read_uword(CPUX86State *env, target_ulong address, target_ulong *value);
bool qebek_read_raw(CPUX86State *env, target_ulong address, uint8_t* buffer, int len);

bool qebek_get_current_pid(CPUX86State *env, uint32_t *pid);

void qebek_log_data(CPUX86State *env, uint16_t type, uint8_t *data, uint32_t len);

#endif
