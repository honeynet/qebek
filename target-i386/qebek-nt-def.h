/*
 * 
 *
 * Copyright (C) 2010 Chengyu Song
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

#ifndef QEBEK_NT_DEF_H
#define QEBEK_NT_DEF_H

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

typedef unsigned char BOOLEAN;
typedef target_ulong ULONG;
typedef target_ulong HANDLE;
typedef unsigned short USHORT;
typedef unsigned int UINT;
typedef unsigned char UCHAR;

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#endif
