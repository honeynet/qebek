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

#ifndef QEBEK_NT_CONSOLESPY_HELPER_H
#define QEBEK_NT_CONSOLESPY_HELPER_H

#include "qebek-nt-linklist.h"

//
// Port handle datastructure management
//
typedef struct _CSRSS_PORT_HANDLE_ENTRY {
   NT_LIST_ENTRY ListEntry;
   ULONG ProcessId;
   HANDLE PortHandle;
   ULONG VirtualOffset;
} CSRSS_PORT_HANDLE_ENTRY, *PCSRSS_PORT_HANDLE_ENTRY;

BOOLEAN
InitPortHandleList(void);

PCSRSS_PORT_HANDLE_ENTRY
GetCsrssHandleEntry(
   IN ULONG ProcessId,
   IN CONST HANDLE PortHandle
   );

BOOLEAN 
IsCsrssPortHandle(
   IN ULONG ProcessId,
   IN HANDLE hPort
   );

ULONG
GetVirtualOffsetFromHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle
   );

VOID
InsertCsrssPortHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle,
   IN ULONG VirtualOffset
   );

VOID
RemoveCsrssPortHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle
   );

#endif
