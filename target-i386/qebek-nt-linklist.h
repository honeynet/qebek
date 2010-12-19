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

#ifndef QEBEK_NT_LINKLIST_H
#define QEBEK_NT_LINKLIST_H

typedef struct _NT_LIST_ENTRY {
   struct _NT_LIST_ENTRY *Flink;
   struct _NT_LIST_ENTRY *Blink;
} NT_LIST_ENTRY, *PNT_LIST_ENTRY;

inline
static
void
InitializeListHead(
    PNT_LIST_ENTRY ListHead
    )
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

inline
static
unsigned char
IsListEmpty(
    const NT_LIST_ENTRY * ListHead
    )
{
    return ListHead->Flink == ListHead;
}

inline
static
void
InsertHeadList(
    PNT_LIST_ENTRY ListHead,
    PNT_LIST_ENTRY Entry
    )
{
    PNT_LIST_ENTRY Flink;

    Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
}

inline
static
unsigned char
RemoveEntryList(
    PNT_LIST_ENTRY Entry
    )
{
    PNT_LIST_ENTRY Blink;
    PNT_LIST_ENTRY Flink;

    Flink = Entry->Flink;
    Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return Flink == Blink;
}

#endif
