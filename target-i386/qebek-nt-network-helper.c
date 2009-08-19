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

#include "qemu-common.h"
#include "osdep.h"
#include "qebek-common.h"
#include "qebek-nt-network-helper.h"

static NT_LIST_ENTRY s_SocketList;
static BOOLEAN s_SocketListInitialized;

// -------------------------------------
//  Socket Management
//
BOOLEAN InitSocketList()
{
	InitializeListHead(&s_SocketList);
	
	s_SocketListInitialized = TRUE;
	
	return TRUE;
}

PSOCKET_ENTRY
GetSocketEntry(
   IN ULONG ProcessId,
   IN CONST HANDLE SocketHandle
   )
{
	if(!s_SocketListInitialized)
		return NULL;

	if (!IsListEmpty(&s_SocketList))
	{
		PSOCKET_ENTRY pCurEntry = NULL;

		pCurEntry = (PSOCKET_ENTRY)s_SocketList.Flink;
		do
		{
			if (pCurEntry->ProcessId == ProcessId && pCurEntry->SocketHandle == SocketHandle)
				return pCurEntry;

			 pCurEntry = (PSOCKET_ENTRY)pCurEntry->ListEntry.Flink;

		} while (pCurEntry != (PSOCKET_ENTRY)&s_SocketList);
	}

	return NULL;
}

BOOLEAN 
IsSocketHandle(
   IN ULONG ProcessId,
   IN HANDLE SocketHandle
   )
{
	PSOCKET_ENTRY Entry;

	if (!s_SocketListInitialized)
		return FALSE;

	Entry = GetSocketEntry(ProcessId, SocketHandle);

	return (Entry != NULL);
}

PSOCKET_ENTRY
InsertSocketHandle(
   IN ULONG ProcessId,
   IN HANDLE SocketHandle
   )
{
	PSOCKET_ENTRY Entry;

	if (!s_SocketListInitialized)
		return NULL;

	Entry = (PSOCKET_ENTRY)qemu_malloc(sizeof(SOCKET_ENTRY));

	if(Entry)
	{
		//fprintf(stderr, "InsertSocketHandle(PID:%d; SocketHandle:%x)\n", ProcessId, SocketHandle);

		memset(Entry, 0, sizeof(SOCKET_ENTRY));
		Entry->SocketHandle = SocketHandle;
		Entry->ProcessId = ProcessId;
		
		Entry->protocol = IPPROTO_IP;

		InsertHeadList(&s_SocketList, &Entry->ListEntry);
	}

	return Entry;
}

VOID
RemoveSocketEntry(
   IN ULONG ProcessId,
   IN HANDLE SocketHandle
   )
{
	PSOCKET_ENTRY Entry;

	if (!s_SocketListInitialized)
		return;

	Entry = GetSocketEntry(ProcessId, SocketHandle);

	if (Entry)
	{
		//fprintf(stderr, "RemoveSocketHandle(PID:%d; SocketHandle:%x)\n", ProcessId, SocketHandle);

		RemoveEntryList(&Entry->ListEntry);
		qemu_free(Entry);
	}   
}

