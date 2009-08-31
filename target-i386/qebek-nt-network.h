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

#ifndef QEBEK_NT_NETWORK_H
#define QEBEK_NT_NETWORK_H

#include "qebek-nt-network-helper.h"

BOOLEAN InitNetwork();

uint16_t index_NtDeviceIoControlFile;
uint16_t index_NtWaitForSingleObject;

uint32_t NtDeviceIoControlFile;
uint32_t NtWaitForSingleObject;

// IoControlCode
#define AFD_BIND				0x12003
#define AFD_CONNECT				0x12007
#define AFD_ACCEPT				0x1200c
#define AFD_DUPLICATE			0x12010
#define AFD_SEND_DATAGRAM		0x12023
#define AFD_SEND                0x1201f
#define AFD_RECV_DATAGRAM       0x1201b
#define AFD_RECV				0x12017
#define AFD_SELECT				0x12024

typedef struct NtDeviceIoControlFileData
{
	uint32_t FileHandle;
	uint32_t EventHandle;
	uint32_t IoStatusBlock;
	uint32_t IoControlCode;
	uint32_t InputBuffer;
	uint32_t OutputBuffer;
}NtDeviceIoControlFileData, *PNtDeviceIoControlFileData;

void preNtDeviceIoControlFile(CPUX86State *env, void* user_data);
void postNtDeviceIoControlFile(CPUX86State *env, void* user_data);

typedef struct NtWaitForSingleObjectData
{
	uint32_t EventHandle;
	uint32_t FileHandle;
	uint32_t IoControlCode;
	uint32_t Buffer;
	uint32_t Status;
}NtWaitForSingleObjectData, *PNtWaitForSingleObjectData;

void preNtWaitForSingleObject(CPUX86State *env, void* user_data);
void postNtWaitForSingleObject(CPUX86State *env, void* user_data);

void OnRecvfromComplete(CPUX86State *env, uint32_t FileHandle, uint32_t Buffer);
void OnAcceptComplete(CPUX86State *env, uint32_t FileHandle, uint32_t Buffer);

void LogRecord(CPUX86State *env, uint8_t call, uint32_t Handle, PSOCKET_ENTRY entry);
#endif
