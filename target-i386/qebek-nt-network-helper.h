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

#ifndef QEBEK_NT_NETWORK_HELPER_H
#define QEBEK_NT_NETWORK_HELPER_H

#include "qebek-nt-linklist.h"

//
// socket management
//
typedef struct _SOCKET_ENTRY {
   NT_LIST_ENTRY ListEntry;
   ULONG ProcessId;
   HANDLE SocketHandle;
   
   UINT dip;
   USHORT dport;
   UINT sip;
   USHORT sport;
   UCHAR protocol;
} SOCKET_ENTRY, *PSOCKET_ENTRY;

BOOLEAN
InitSocketList(void);

PSOCKET_ENTRY
GetSocketEntry(
   IN ULONG ProcessId,
   IN CONST HANDLE SocketHandle
   );

BOOLEAN 
IsSocketHandle(
   IN ULONG ProcessId,
   IN HANDLE hSocket
   );

PSOCKET_ENTRY
InsertSocketHandle(
   IN ULONG ProcessId,
   IN HANDLE SocketHandle
   );

VOID
RemoveSocketEntry(
   IN ULONG ProcessId,
   IN HANDLE SocketHandle
   );

#endif
