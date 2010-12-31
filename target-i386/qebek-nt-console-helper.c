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

#include "qemu-common.h"
#include "osdep.h"
#include "qebek-common.h"
#include "qebek-nt-def.h"
#include "qebek-nt-console-helper.h"

static NT_LIST_ENTRY s_PortHandleList;
static BOOLEAN s_PortDataInitialized;

// -------------------------------------
// Port Handle Data Structure Management
//
BOOLEAN InitPortHandleList(void)
{
	InitializeListHead(&s_PortHandleList);
	
	s_PortDataInitialized = TRUE;
	
	return TRUE;
}

PCSRSS_PORT_HANDLE_ENTRY
GetCsrssHandleEntry(
   IN ULONG ProcessId,
   IN CONST HANDLE PortHandle
   )
{
   if (!IsListEmpty(&s_PortHandleList))
   {
      PCSRSS_PORT_HANDLE_ENTRY pCurEntry = 0;

      pCurEntry = (PCSRSS_PORT_HANDLE_ENTRY)s_PortHandleList.Flink;
      do
      {
         if (pCurEntry->ProcessId == ProcessId && pCurEntry->PortHandle == PortHandle)
            return pCurEntry;

         pCurEntry = (PCSRSS_PORT_HANDLE_ENTRY)pCurEntry->ListEntry.Flink;

      } while (pCurEntry != (PCSRSS_PORT_HANDLE_ENTRY)&s_PortHandleList);
   }

   return 0;
}

BOOLEAN 
IsCsrssPortHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle
   )
{
   BOOLEAN bCsrssHandle = FALSE;
   PCSRSS_PORT_HANDLE_ENTRY Entry;

   if (!s_PortDataInitialized)
      return FALSE;

   Entry = GetCsrssHandleEntry(ProcessId, PortHandle);
   if (Entry)
      bCsrssHandle = TRUE;

   return bCsrssHandle;
}

ULONG
GetVirtualOffsetFromHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle
   )
{
   ULONG VirtualOffset = 0;
   PCSRSS_PORT_HANDLE_ENTRY Entry;

   if (!s_PortDataInitialized)
      return FALSE;

   //fprintf(stderr, "GetVirtualOffsetFromHandle(PID:%xh; PortHandle:%xh)\n", ProcessId, PortHandle);

   Entry = GetCsrssHandleEntry(ProcessId, PortHandle);
   if (Entry)
      VirtualOffset = Entry->VirtualOffset;

   return VirtualOffset;
}

VOID
InsertCsrssPortHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle,
   IN ULONG VirtualOffset
   )
{
   PCSRSS_PORT_HANDLE_ENTRY Entry;

   if (!s_PortDataInitialized)
      return;

   Entry = (PCSRSS_PORT_HANDLE_ENTRY)qemu_malloc(sizeof(CSRSS_PORT_HANDLE_ENTRY));

   if (!Entry)
      return;

   //fprintf(stderr, "InsertCsrssPortHandle(PID:%xh; PortHandle:%xh; Offset:0x%08x)\n", ProcessId, PortHandle, VirtualOffset);

   Entry->PortHandle = PortHandle;
   Entry->ProcessId = ProcessId;
   Entry->VirtualOffset = VirtualOffset;

   InsertHeadList(&s_PortHandleList, &Entry->ListEntry);
}

VOID
RemoveCsrssPortHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle
   )
{
   PCSRSS_PORT_HANDLE_ENTRY Entry;

   if (!s_PortDataInitialized)
      return;

   Entry = GetCsrssHandleEntry(ProcessId, PortHandle);

   if (Entry)
   {
      //fprintf(stderr, "RemoveCsrssPortHandle(PID:%x; PortHandle:%xh)\n", ProcessId, PortHandle);

      RemoveEntryList(&Entry->ListEntry);
      qemu_free(Entry);
   }
   
}

