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
#include <arpa/inet.h>
#include "osdep.h"
#include "qebek-common.h"
#include "qebek-bp.h"
#include "qebek-nt-network.h"
#include "qebek-nt-network-helper.h"

BOOLEAN InitNetwork()
{
	if(!InitSocketList())
		return FALSE;

	return TRUE;
}

void preNtDeviceIoControlFile(CPUX86State *env, void* user_data)
{
	uint32_t FileHandle, IoControlCode, InputBuffer, OutputBuffer, EventHandle, IoStatusBlock;
	PNtDeviceIoControlFileData pControlData;
	target_ulong ret_addr;

	// get file handle, buffer & buffer size from stack
    qebek_read_ulong(env, env->regs[R_ESP] + 4, &FileHandle);
	qebek_read_ulong(env, env->regs[R_ESP] + 2 * 4, &EventHandle);
	qebek_read_ulong(env, env->regs[R_ESP] + 5 * 4, &IoStatusBlock);
    qebek_read_ulong(env, env->regs[R_ESP] + 6 * 4, &IoControlCode);
    qebek_read_ulong(env, env->regs[R_ESP] + 7 * 4, &InputBuffer);
	qebek_read_ulong(env, env->regs[R_ESP] + 9 * 4, &OutputBuffer);
	
	switch(IoControlCode)
	{
	case AFD_BIND:
	case AFD_CONNECT:
	case AFD_SEND_DATAGRAM:
	case AFD_RECV_DATAGRAM:
	case AFD_SEND:
	case AFD_RECV:
	case AFD_ACCEPT:
	case AFD_DUPLICATE:
	case AFD_SELECT:
		break;
	default:
		return; // only handle network related calling
	}
	
	//fprintf(stderr, "preNtDeviceIoControlFile: FileHandle %08x, IoControlCode %08x, InputBuffer %08x, OutputBuffer %08x\n", 
	//		FileHandle, IoControlCode, InputBuffer, OutputBuffer);
	
	pControlData = (PNtDeviceIoControlFileData)qemu_malloc(sizeof(NtDeviceIoControlFileData));
	if(pControlData)
	{
		pControlData->FileHandle = FileHandle;
		pControlData->EventHandle = EventHandle;
		pControlData->IoStatusBlock = IoStatusBlock;
		pControlData->IoControlCode = IoControlCode;
		pControlData->InputBuffer = InputBuffer;
		pControlData->OutputBuffer = OutputBuffer;
	}
	
	// set return address, so the VM will break when returned
	qebek_read_ulong(env, env->regs[R_ESP], &ret_addr);
	if(!qebek_bp_add(ret_addr, env->cr[3], env->regs[R_EBP], postNtDeviceIoControlFile, pControlData))
	{
		fprintf(stderr, "preNtDeviceIoControlFile: failed to add postcall interception.\n");
	}
}

void postNtDeviceIoControlFile(CPUX86State *env, void* user_data)
{
	uint32_t FileHandle, IoControlCode, InputBuffer, OutputBuffer, EventHandle, IoStatusBlock;
	uint32_t PID, ntStatus, SocketHandle;
	PNtDeviceIoControlFileData pControlData;
	PSOCKET_ENTRY pSocketEntry, pSocketEntry2;
	PNtWaitForSingleObjectData pWaitData;
	uint32_t ip, addr_in;
	uint16_t port;
	target_ulong ip_addr, port_addr, addr_addr, bp_addr, sh_addr;

	
	pControlData = (PNtDeviceIoControlFileData)user_data;
	if(pControlData == NULL)
	{
		//get file handle, control code, input buffer and output buffer
		qebek_read_ulong(env, env->regs[R_ESP] - 10 * 4, &FileHandle);
		qebek_read_ulong(env, env->regs[R_ESP] - 9 * 4, &EventHandle);
		qebek_read_ulong(env, env->regs[R_ESP] - 6 * 4, &IoStatusBlock);
		qebek_read_ulong(env, env->regs[R_ESP] - 5 * 4, &IoControlCode);
		qebek_read_ulong(env, env->regs[R_ESP] - 4 * 4, &InputBuffer);
		qebek_read_ulong(env, env->regs[R_ESP] - 2 * 4, &OutputBuffer);
	}
	else
	{
		FileHandle = pControlData->FileHandle;
		EventHandle = pControlData->EventHandle;
		IoStatusBlock = pControlData->IoStatusBlock;
		IoControlCode = pControlData->IoControlCode;
		InputBuffer = pControlData->InputBuffer;
		OutputBuffer = pControlData->OutputBuffer;

		qemu_free(pControlData);
	}

	//fprintf(stderr, "postNtDeviceIoControlFile: FileHandle %08x, IoControlCode %08x, InputBuffer %08x, OutputBuffer %08x\n", 
	//		FileHandle, IoControlCode, InputBuffer, OutputBuffer);
	
	//if(!qebek_get_current_pid(env, &PID))
	//	goto remove_bp;
	PID = env->cr[3];

	ntStatus = env->regs[R_EAX];
	if(ntStatus != 0 &&
			ntStatus != 0x103 // STATUS_PENDING
	  )
		goto remove_bp;

	switch(IoControlCode)
	{
	case AFD_BIND:

		ip_addr = InputBuffer + 0x0e;
		port_addr = OutputBuffer + 0x0c;

		if(!qebek_read_ulong(env, ip_addr, &ip))
		{
			fprintf(stderr, "postNtDeviceIoControlFile: failed to read bind ip: %08x\n", ip_addr);
			break;
		}

		if(!qebek_read_uword(env, port_addr, &port))
		{
			fprintf(stderr, "postNtDeviceIoControlFile: failed to read bind port: %08x\n", port_addr);
			break;
		}

		if((pSocketEntry = GetSocketEntry(PID, FileHandle)) == NULL)
		{
			if((pSocketEntry = InsertSocketHandle(PID, FileHandle)) == NULL)
			{
				fprintf(stderr, "postNtDeviceIoControlFile: failed to insert socket entry\n");
				break;
			}
		}

		pSocketEntry->sip = ip;
		pSocketEntry->sport = port;

		break;

	case AFD_CONNECT:

		ip_addr = InputBuffer + 0x16;
		port_addr = InputBuffer + 0x14;

		if(!qebek_read_ulong(env, ip_addr, &ip))
		{
			fprintf(stderr, "postNtDeviceIoControlFile: failed to read connect ip: %08x\n", ip_addr);
			break;
		}

		if(!qebek_read_uword(env, port_addr, &port))
		{
			fprintf(stderr, "postNtDeviceIoControlFile: failed to read connect port: %08x\n", port_addr);
			break;
		}

		/*dip = ntohl(ip);
		dport = ntohs(port);
		fprintf(stderr, "connect to %hu.%hu.%hu.%hu:%hu, using handle %x\n", 
				(short)((dip >> 24) & 0xff), (short)((dip >> 16) & 0xff), (short)((dip >> 8) & 0xff),
				(short)(dip & 0xff), dport, FileHandle);*/

		SocketHandle = 0;
		sh_addr = InputBuffer + 0x08;
		if(!qebek_read_ulong(env, sh_addr, &SocketHandle))
		{
			fprintf(stderr, "postNtDeviceIoControlFile: failed to read socket handle: %08x\n", sh_addr);
		}
		if(SocketHandle == 0)
			SocketHandle = FileHandle;
		
		if((pSocketEntry = GetSocketEntry(PID, SocketHandle)) == NULL)
			break; // not sure

		pSocketEntry->dip = ip;
		pSocketEntry->dport = port;
		pSocketEntry->protocol = IPPROTO_TCP;
		
		LogRecord(env, SYS_CONNECT, SocketHandle, pSocketEntry);

		break;
		
	case AFD_SEND:
		if((pSocketEntry = GetSocketEntry(PID, FileHandle)) != NULL)
			LogRecord(env, SYS_SENDMSG, FileHandle, pSocketEntry);
		else
		{
			fprintf(stderr, "postNtDeviceIoControlFile: failed to get socket entry for send: %08x\n", FileHandle);
		}

		break;

	case AFD_RECV:
		if((pSocketEntry = GetSocketEntry(PID, FileHandle)) != NULL)
			LogRecord(env, SYS_RECVMSG, FileHandle, pSocketEntry);
		else
		{
			fprintf(stderr, "postNtDeviceIoControlFIle: failed to get socket entry for recv: %08x\n", FileHandle);
		}

		break;

	case AFD_SEND_DATAGRAM:
		
		addr_addr = InputBuffer + 0x34;
		if(!qebek_read_ulong(env, addr_addr, &addr_in))
		{
			fprintf(stderr, "postNtDeviceIoControlFile: failed to read sendto sockaddr_in: %08x\n", addr_addr);
			break;
		}

		ip_addr = addr_in + 0x0a;
		port_addr = addr_in + 0x08;
		
		if(!qebek_read_ulong(env, ip_addr, &ip))
		{
			fprintf(stderr, "postNtDeviceIoControlFile: failed to read sendto ip: %08x\n", ip_addr);
			break;
		}

		if(!qebek_read_uword(env, port_addr, &port))
		{
			fprintf(stderr, "postNtDeviceIoControlFile: failed to read sendto port: %08x\n", port_addr);
			break;
		}

		if((pSocketEntry = GetSocketEntry(PID, FileHandle)) == NULL)
			break; // not sure

		pSocketEntry->dip = ip;
		pSocketEntry->dport = port;
		pSocketEntry->protocol = IPPROTO_UDP;
		
		LogRecord(env, SYS_SENDTO, FileHandle, pSocketEntry);

		break;

	case AFD_RECV_DATAGRAM:
		if(ntStatus == 0)
		{
			OnRecvfromComplete(env, FileHandle, InputBuffer);
		}
		else if(ntStatus == 0x103)
		{
			pWaitData = (PNtWaitForSingleObjectData)qemu_malloc(sizeof(NtWaitForSingleObjectData));
			if(!pWaitData)
			{
				fprintf(stderr, "postNtDeviceIoControlFile: failed to malloc wait data\n");
				break;
			}

			pWaitData->EventHandle = EventHandle;
			pWaitData->FileHandle = FileHandle;
			pWaitData->IoControlCode = IoControlCode;
			pWaitData->Buffer = InputBuffer;
			pWaitData->Status = IoStatusBlock;

			if(!qebek_bp_add(NtWaitForSingleObject, env->cr[3], env->regs[R_EBP], preNtWaitForSingleObject, pWaitData))
			{
				fprintf(stderr, "postNtDeviceIoControlFile: failed to add wait bp\n");
				qemu_free(pWaitData);
			}
		}

		break;

	case AFD_ACCEPT:
		if(ntStatus == 0)
		{
			OnAcceptComplete(env, FileHandle, OutputBuffer);
		}
		else if(ntStatus == 0x103)
		{
			pWaitData = (PNtWaitForSingleObjectData)qemu_malloc(sizeof(NtWaitForSingleObjectData));
			if(!pWaitData)
			{
				fprintf(stderr, "postNtDeviceIoControlFile: failed to malloc wait data2\n");
				break;
			}

			pWaitData->EventHandle = EventHandle;
			pWaitData->FileHandle = FileHandle;
			pWaitData->IoControlCode = IoControlCode;
			pWaitData->Buffer = OutputBuffer;
			pWaitData->Status = IoStatusBlock;

			if(!qebek_bp_add(NtWaitForSingleObject, env->cr[3], env->regs[R_EBP], preNtWaitForSingleObject, pWaitData))
			{
				fprintf(stderr, "postNtDeviceIoControlFile: failed to add wait bp2\n");
				qemu_free(pWaitData);
			}
		}

		break;

	case AFD_DUPLICATE:
		sh_addr = InputBuffer + 0x08;
		if(!qebek_read_ulong(env, sh_addr, &SocketHandle))
		{
			fprintf(stderr, "postNtDeviceIoControlFile: failed to read new socket handle: %08x\n", sh_addr);
			break;
		}

		if((pSocketEntry = GetSocketEntry(PID, FileHandle)) == NULL)
		{
			fprintf(stderr, "psotNtDeviceIoControlFile: failed to get old socket entry: %08x\n", FileHandle);
			break;
		}

		if((pSocketEntry2 = InsertSocketHandle(PID, SocketHandle)) == NULL)
		{
			fprintf(stderr, "postNtDeviceIoControlFile: failed to insert new socket entry: %08x\n", SocketHandle);
			break;
		}

		memcpy(pSocketEntry2, pSocketEntry, sizeof(SOCKET_ENTRY));

		break;

	case AFD_SELECT:
		//fprintf(stderr, "AFD_SELECT\n");

		break;

	default:
		break;
	}


remove_bp:
	// remove return address
    bp_addr = env->eip;
    if(!qebek_bp_remove(bp_addr, env->cr[3], env->regs[R_EBP]))
    {
        fprintf(stderr, "postNtDeviceIoControlFile: failed to remove postcall interception.\n");
    }
}

void OnRecvfromComplete(CPUX86State *env, uint32_t FileHandle, uint32_t Buffer)
{
	PSOCKET_ENTRY pSocketEntry;
	uint32_t ip, addr_in;
	uint16_t port;
	target_ulong ip_addr, port_addr, addr_addr;

	addr_addr = Buffer + 0x10;
	if(!qebek_read_ulong(env, addr_addr, &addr_in))
	{
		fprintf(stderr, "OnRecvComplete: failed to read recvfrom sockaddr_in: %08x\n", addr_addr);
		return;
	}

	ip_addr = addr_in + 0x04;
	port_addr = addr_in + 0x02;
		
	if(!qebek_read_ulong(env, ip_addr, &ip))
	{
		fprintf(stderr, "OnRecvComplete: failed to read recvfrom ip: %08x\n", ip_addr);
		return;
	}

	if(!qebek_read_uword(env, port_addr, &port))
	{
		fprintf(stderr, "OnRecvComplete: failed to read recvfrom port: %08x\n", port_addr);
		return;
	}

	if((pSocketEntry = GetSocketEntry(env->cr[3], FileHandle)) == NULL)
		return; // not sure

	pSocketEntry->dip = ip;
	pSocketEntry->dport = port;
	pSocketEntry->protocol = IPPROTO_UDP;
		
	LogRecord(env, SYS_RECVFROM, FileHandle, pSocketEntry);
}

void OnAcceptComplete(CPUX86State *env, uint32_t FileHandle, uint32_t Buffer)
{
	PSOCKET_ENTRY pSocketEntry;
	uint32_t ip;
	uint16_t port;
	target_ulong ip_addr, port_addr;

	ip_addr = Buffer + 0x0e;
	port_addr = Buffer + 0x0c;
		
	if(!qebek_read_ulong(env, ip_addr, &ip))
	{
		fprintf(stderr, "OnAcceptComplete: failed to read accepted ip: %08x\n", ip_addr);
		return;
	}

	if(!qebek_read_uword(env, port_addr, &port))
	{
		fprintf(stderr, "OnAcceptComplete: failed to read accepted port: %08x\n", port_addr);
		return;
	}

	if((pSocketEntry = GetSocketEntry(env->cr[3], FileHandle)) == NULL)
		return; // not sure

	pSocketEntry->dip = ip;
	pSocketEntry->dport = port;
	pSocketEntry->protocol = IPPROTO_TCP;
		
	LogRecord(env, SYS_ACCEPT, FileHandle, pSocketEntry);
}

void preNtWaitForSingleObject(CPUX86State *env, void* user_data)
{
	uint32_t Handle;
	PNtWaitForSingleObjectData pWaitData;
	target_ulong ret_addr, bp_addr;

	qebek_read_ulong(env, env->regs[R_ESP] + 4, &Handle);

	//fprintf(stderr, "preNtWaitForSingleObject: Handle %08x\n", Handle);

	pWaitData = (PNtWaitForSingleObjectData)user_data;
	if(Handle != pWaitData->EventHandle)
		return;

	// set return address, so the VM will break when returned
	qebek_read_ulong(env, env->regs[R_ESP], &ret_addr);
	if(!qebek_bp_add(ret_addr, env->cr[3], env->regs[R_EBP], postNtWaitForSingleObject, pWaitData))
	{
		fprintf(stderr, "preNtWaitForSingleObject: failed to add postcall interception.\n");
	}

	// remove self
	bp_addr = env->eip;
    if(!qebek_bp_remove(bp_addr, env->cr[3], env->regs[R_EBP]))
    {
        fprintf(stderr, "preNtWaitForSingleObject: failed to remove precall interception.\n");
    }
}

void postNtWaitForSingleObject(CPUX86State *env, void* user_data)
{
	uint32_t Status;
	target_ulong bp_addr;
	PNtWaitForSingleObjectData pWaitData = (PNtWaitForSingleObjectData)user_data;

	//fprintf(stderr, "postNtWaitForSingleObject: Handle %08x\n", pWaitData->EventHandle);
	
	qebek_read_ulong(env, pWaitData->Status, &Status);
	if(Status != 0)
		goto remove_bp;

	switch(pWaitData->IoControlCode)
	{
	case AFD_RECV_DATAGRAM:
		OnRecvfromComplete(env, pWaitData->FileHandle, pWaitData->Buffer);
		break;

	case AFD_ACCEPT:
		OnAcceptComplete(env, pWaitData->FileHandle, pWaitData->Buffer);
		break;

	default:
		break;
	}

remove_bp:
	qemu_free(pWaitData);

	bp_addr = env->eip;
    if(!qebek_bp_remove(bp_addr, env->cr[3], env->regs[R_EBP]))
    {
        fprintf(stderr, "postNtWaitForSingleObject: failed to remove postcall interception.\n");
    }
}

void LogRecord(CPUX86State *env, uint8_t call, uint32_t handle, PSOCKET_ENTRY entry)
{
	struct sbk_sock_rec record;
	uint32_t sip, dip;
	uint16_t sport, dport;

	if(!entry)
		return;
	
	/*dip = ntohl(entry->dip);
	dport = ntohs(entry->dport);
	sip = ntohl(qebek_g_ip);
	sport = ntohs(entry->sport);

	fprintf(stderr, "%d: %hu.%hu.%hu.%hu:%hu -> %hu.%hu.%hu.%hu:%hu\n", call,
			(short)((sip >> 24) & 0xff), (short)((sip >> 16) & 0xff), (short)((sip >> 8) & 0xff), (short)(sip & 0xff), sport,
			(short)((dip >> 24) & 0xff), (short)((dip >> 16) & 0xff), (short)((dip >> 8) & 0xff), (short)(dip & 0xff), dport);
	*/
	record.dip = entry->dip;
	record.dport = entry->dport;
	//if(entry->sip == 0 || entry->sip == 0x7f000001)
		record.sip = qebek_g_ip;
	//else
	//	record.sip = entry->sip;
	record.sport = entry->sport;
	record.call = htons(call);
	record.proto = entry->protocol;

	qebek_log_data(env, SEBEK_TYPE_SOCKET, (uint8_t *)&record, sizeof(record));
}
