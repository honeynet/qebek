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

#ifndef QEBEK_CONSOLESPY_H
#define QEBEK_CONSOLESPY_H

uint32_t NtRequestWaitReplyPort;
uint32_t NtSecureConnectPort;
uint32_t NtClose;
uint32_t NtWriteFile;
uint32_t NtReadFile;

uint32_t NtWriteFilePost;
uint32_t NtReadFilePost;

HANDLE ReadHandle;
ULONG ReadBuffer;
ULONG ReadSize;

HANDLE WriteHandle;
ULONG WriteBuffer;
ULONG WriteSize;

BOOLEAN IsHandleStd(CPUX86State *env, CONST HANDLE Handle);

VOID OnNtReadWriteFile(CPUX86State *env, HANDLE Handle, ULONG Buffer, ULONG BufferSize);

#endif
