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

#ifndef QEBEK_NT_CONSOLESPY_H
#define QEBEK_NT_CONSOLESPY_H

#include "qebek-nt-def.h"

extern uint16_t index_NtRequestWaitReplyPort;
extern uint16_t index_NtSecureConnectPort;
extern uint16_t index_NtClose;
extern uint16_t index_NtReadFile;
extern uint16_t index_NtWriteFile;
extern uint16_t index_NtCreateThread;

extern uint32_t NtRequestWaitReplyPort;
extern uint32_t NtSecureConnectPort;
extern uint32_t NtClose;
extern uint32_t NtWriteFile;
extern uint32_t NtReadFile;
extern uint32_t NtCreateThread;

BOOLEAN InitConsoleSpy(void);

BOOLEAN IsHandleStd(CPUX86State *env, CONST HANDLE Handle);
VOID OnNtReadWriteFile(CPUX86State *env, HANDLE Handle, ULONG Buffer, ULONG BufferSize);

typedef struct NtReadWriteData
{
	uint32_t FileHandle;
	uint32_t Buffer;
	uint32_t BufferSize;
}NtReadWriteData, *PNtReadWriteData;

typedef struct NtConnectPortData
{
	uint32_t PortHandle;
	uint32_t PortName;
	uint32_t WriteSection;
}NtConnectPortData, *PNtConnectPortData;

typedef struct NtRequestPortData
{
	uint32_t Message;
	uint32_t VirtualOffset;
}NtRequestPortData, *PNtRequestPortData;

void preNtRequestWaitReplyPort(CPUX86State *env, void* user_data);
void postNtRequestWaitReplyPort(CPUX86State *env, void* user_data);
void preNtSecureConnectPort(CPUX86State *env, void* user_data);
void postNtSecureConnectPort(CPUX86State *env, void* user_data);
void preNtClose(CPUX86State *env, void* user_data);
void postNtClose(CPUX86State *env, void* user_data);
void preNtReadFile(CPUX86State *env, void* user_data);
void postNtReadFile(CPUX86State *env, void* user_data);
void preNtWriteFile(CPUX86State *env, void* user_data);
void postNtWriteFile(CPUX86State *env, void* user_data);

void preNtCreateThread(CPUX86State *env, void* user_data);
void postNtCreateThread(CPUX86State *env, void* user_data);

//
// TODO: Check the current version before choosing an opcode
//
#define  OPCODE_READ_CONSOLE        0x2021D
#define  OPCODE_WRITE_CONSOLE       0x2021E

#define CONSOLE_WRITE_INFO_MESSAGE_BUFFER_SIZE  80
#define CONSOLE_READ_INFO_MESSAGE_BUFFER_SIZE   82

void OnCsrWriteDataPre(CPUX86State *env, ULONG Message, ULONG VirtualOffset);
void OnCsrReadDataPost(CPUX86State *env, ULONG Message, ULONG VirtualOffset);

bool UnicodeToAnsiString(uint8_t *buffer, uint16_t *length);
bool DummyUnicodeToAnsiString(uint8_t *buffer, uint16_t *length);

#endif
