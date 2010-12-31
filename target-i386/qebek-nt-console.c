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
#include <wchar.h>
#include "osdep.h"
#include "qebek-common.h"
#include "qebek-bp.h"
#include "qebek-nt-console.h"
#include "qebek-nt-console-helper.h"
#include "qebek-nt-network-helper.h"

uint16_t index_NtRequestWaitReplyPort;
uint16_t index_NtSecureConnectPort;
uint16_t index_NtClose;
uint16_t index_NtReadFile;
uint16_t index_NtWriteFile;
uint16_t index_NtCreateThread;

uint32_t NtRequestWaitReplyPort;
uint32_t NtSecureConnectPort;
uint32_t NtClose;
uint32_t NtWriteFile;
uint32_t NtReadFile;
uint32_t NtCreateThread;

BOOLEAN InitConsoleSpy(void)
{
	if(!InitPortHandleList())
	{
		fprintf(stderr, "InitConsoleSpy: failed to initialize port handle list.\n");
		return False;
	}

	return True;
}

BOOLEAN IsHandleStd(CPUX86State *env, CONST HANDLE Handle)
{
	target_ulong pkthread = env->segs[R_FS].base + 0x124;
    target_ulong pteb, ppeb, pproc_param;
	target_ulong kthread, teb, peb, proc_param;
	uint32_t stdin_handle, stdout_handle, stderr_handle;
		
	// get KPCR.KPRCB->KTHREAD->TEB->PEB->ProcessParameters
	if(!qebek_read_ulong(env, pkthread, &kthread))
	{
		fprintf(stderr, "LogIfStdHandle: failed to read kthread\n");
		return False;
	}

	pteb = kthread + 0x20;
	if(!qebek_read_ulong(env, pteb, &teb))
	{
		fprintf(stderr, "LogIfStdHandle: failed to read teb, pointer %08X\n", pteb);
		return False;
	}

	if(teb == 0)
		return False;

	ppeb = teb + 0x30;
	if(!qebek_read_ulong(env, ppeb, &peb))
    {
        fprintf(stderr, "LogIfStdHandle: failed to read peb, pointer %08X\n", ppeb);
        return False;
    }

	if(peb == 0)
		return False;

	pproc_param = peb + 0x10;
	if(!qebek_read_ulong(env, pproc_param, &proc_param))
    {
        fprintf(stderr, "LogIfStdHandle: failed to read process_parameters, pointer %08X\n", pproc_param);
        return False;
    }

	// get stdin,sdtout,stderr
	qebek_read_ulong(env, proc_param+0x18, &stdin_handle);
	qebek_read_ulong(env, proc_param+0x1c, &stdout_handle);
	qebek_read_ulong(env, proc_param+0x20, &stderr_handle);

	if(Handle == stdin_handle ||
		Handle == stdout_handle ||
		Handle == stderr_handle)
	{
		fprintf(stderr, "LogIfStdHandle: std handle\n");
		return True;
	}

	return False;
}

VOID OnNtReadWriteFile(CPUX86State *env, HANDLE Handle, ULONG Buffer, ULONG BufferSize)
{
	uint8_t *buffer;

	if(!IsHandleStd(env, Handle))
		return;
	
	buffer = qemu_malloc(BufferSize + 1);
	if(buffer == NULL)
	{
		fprintf(stderr, "OnNtReadWriteFile: failed to alloc buffer\n");
		return;
	}
	memset(buffer, 0, BufferSize + 1);

	if(!qebek_read_raw(env, Buffer, buffer, BufferSize))
	{
		fprintf(stderr, "OnNtReadWriteFile: failed to read buffer: %x %x\n", Buffer, BufferSize);
	}
	else
	{
		// log
		qebek_log_data(env, SEBEK_TYPE_READ, buffer, BufferSize);
	}

	qemu_free(buffer);
}

void preNtReadFile(CPUX86State *env, void* user_data)
{
	uint32_t ReadHandle, ReadBuffer, ReadSize;
	target_ulong ret_addr;
	PNtReadWriteData pReadData;

	// get file handle, buffer & buffer size from stack
    qebek_read_ulong(env, env->regs[R_ESP] + 4, &ReadHandle);
    qebek_read_ulong(env, env->regs[R_ESP] + 6 * 4, &ReadBuffer);
    qebek_read_ulong(env, env->regs[R_ESP] + 7 * 4, &ReadSize);	
	
	//fprintf(stderr, "preNtReadFile: FileHandle %08x, Buffer %08x, Size %08x\n", ReadHandle, ReadBuffer, ReadSize);

	pReadData = (PNtReadWriteData)qemu_malloc(sizeof(NtReadWriteData));
	if(pReadData != NULL)
	{
		pReadData->FileHandle = ReadHandle;
		pReadData->Buffer = ReadBuffer;
		pReadData->BufferSize = ReadSize;
	}
	        
	// set return address, so the VM will break when returned
	qebek_read_ulong(env, env->regs[R_ESP], &ret_addr);
	if(!qebek_bp_add(ret_addr, env->cr[3], env->regs[R_EBP], postNtReadFile, pReadData))
	{
		fprintf(stderr, "preNtReadFile: failed to add postcall interception.\n");
	}
}

void postNtReadFile(CPUX86State *env, void* user_data)
{
	uint32_t ReadHandle, ReadBuffer, ReadSize;
	target_ulong bp_addr;
	PNtReadWriteData pReadData = (PNtReadWriteData)user_data;

	if(pReadData == NULL)
	{
		// get file handle, buffer & buffer size from stack
		qebek_read_ulong(env, env->regs[R_ESP] - 9 * 4, &ReadHandle);
		qebek_read_ulong(env, env->regs[R_ESP] - 4 * 4, &ReadBuffer);
		qebek_read_ulong(env, env->regs[R_ESP] - 3 * 4, &ReadSize);
	}
	else
	{
		ReadHandle = pReadData->FileHandle;
		ReadBuffer = pReadData->Buffer;
		ReadSize = pReadData->BufferSize;

		qemu_free(pReadData);
	}

	//fprintf(stderr, "postNtReadFile: FileHandle %08x, Buffer %08x, Size %08x\n", ReadHandle, ReadBuffer, ReadSize);
	
	// if succeed
	if(env->regs[R_EAX] == 0)
		OnNtReadWriteFile(env, ReadHandle, ReadBuffer, ReadSize);

	// remove return address
	bp_addr = env->eip;
	if(!qebek_bp_remove(bp_addr, env->cr[3], env->regs[R_EBP]))
	{
		fprintf(stderr, "postNtReadFile: failed to remove postcall interception.\n");
	}
}

void preNtWriteFile(CPUX86State *env, void* user_data)
{
    uint32_t WriteHandle, WriteBuffer, WriteSize;
    target_ulong ret_addr;
	PNtReadWriteData pWriteData;

    // get file handle, buffer & buffer size from stack
    qebek_read_ulong(env, env->regs[R_ESP] + 4, &WriteHandle);
    qebek_read_ulong(env, env->regs[R_ESP] + 6 * 4, &WriteBuffer);
    qebek_read_ulong(env, env->regs[R_ESP] + 7 * 4, &WriteSize);

    //fprintf(stderr, "preNtWriteFile: FileHandle %08x, Buffer %08x, Size %08x\n", WriteHandle, WriteBuffer, WriteSize);

	pWriteData = (PNtReadWriteData)qemu_malloc(sizeof(NtReadWriteData));
	if(pWriteData != NULL)
	{
		pWriteData->FileHandle = WriteHandle;
		pWriteData->Buffer = WriteBuffer;
		pWriteData->BufferSize = WriteSize;
	}

    // set return address, so the VM will break when returned
    qebek_read_ulong(env, env->regs[R_ESP], &ret_addr);
    if(!qebek_bp_add(ret_addr, env->cr[3], env->regs[R_EBP], postNtWriteFile, pWriteData))
    {
        fprintf(stderr, "preNtWriteFile: failed to add postcall interception.\n");
    }
}

void postNtWriteFile(CPUX86State *env, void* user_data)
{
    uint32_t WriteHandle, WriteBuffer, WriteSize;
    target_ulong bp_addr;
	PNtReadWriteData pWriteData = (PNtReadWriteData)user_data;

	if(pWriteData == NULL)
	{
		// get file handle, buffer & buffer size from stack
		qebek_read_ulong(env, env->regs[R_ESP] - 9 * 4, &WriteHandle);
		qebek_read_ulong(env, env->regs[R_ESP] - 4 * 4, &WriteBuffer);
		qebek_read_ulong(env, env->regs[R_ESP] - 3 * 4, &WriteSize);
	}
	else
	{
		WriteHandle = pWriteData->FileHandle;
		WriteBuffer = pWriteData->Buffer;
		WriteSize = pWriteData->BufferSize;

		qemu_free(pWriteData);
	}

    //fprintf(stderr, "postNtWriteFile: FileHandle %08x, Buffer %08x, Size %08x\n", WriteHandle, WriteBuffer, WriteSize);

    // if succeed
    if(env->regs[R_EAX] == 0)
        OnNtReadWriteFile(env, WriteHandle, WriteBuffer, WriteSize);

    // remove return address
    bp_addr = env->eip;
    if(!qebek_bp_remove(bp_addr, env->cr[3], env->regs[R_EBP]))
    {
        fprintf(stderr, "postNtWriteFile: failed to remove postcall interception.\n");
    }
}

void preNtSecureConnectPort(CPUX86State *env, void* user_data)
{
    uint32_t PortHandle, PortName, WriteSection;
    target_ulong ret_addr;
	PNtConnectPortData pPortData;

    // get port handle, port & write section from stack
    qebek_read_ulong(env, env->regs[R_ESP] + 4, &PortHandle);
    qebek_read_ulong(env, env->regs[R_ESP] + 2 * 4, &PortName);
    qebek_read_ulong(env, env->regs[R_ESP] + 4 * 4, &WriteSection);

    //fprintf(stderr, "preNtSecureConnectPort: PortHandle %08x, PortName %08x, WriteSection %08x\n", PortHandle, PortName, WriteSection);

	pPortData = (PNtConnectPortData)qemu_malloc(sizeof(NtConnectPortData));
	if(pPortData != NULL)
	{
		pPortData->PortHandle = PortHandle;
		pPortData->PortName = PortName;
		pPortData->WriteSection = WriteSection;
	}

    // set return address, so the VM will break when returned
    qebek_read_ulong(env, env->regs[R_ESP], &ret_addr);
    if(!qebek_bp_add(ret_addr, env->cr[3], env->regs[R_EBP], postNtSecureConnectPort, pPortData))
    {
        fprintf(stderr, "preNtSecureConnectPort: failed to add postcall interception.\n");
    }
}

void postNtSecureConnectPort(CPUX86State *env, void* user_data)
{
    uint32_t pPortHandle, pPortName, pWriteSection;
    target_ulong bp_addr, name_buffer;
	uint16_t name_length;
	char port_name[34];
	char target_name[32] = {'\\',0,'W',0,'i',0,'n',0,'d',0,'o',0,'w',0,'s',0,'\\',0,'A',0,'p',0,'i',0,'P',0,'o',0,'r',0,'t',0};
	PNtConnectPortData pPortData = (PNtConnectPortData)user_data;
	uint32_t PortHandle, VirtualOffset, TargetViewBase, ViewBase, PID;

	if(pPortData == NULL)
	{
		// get port handle, port anme & write section from stack
		qebek_read_ulong(env, env->regs[R_ESP] - 9 * 4, &pPortHandle);
		qebek_read_ulong(env, env->regs[R_ESP] - 8 * 4, &pPortName);
		qebek_read_ulong(env, env->regs[R_ESP] - 6 * 4, &pWriteSection);
	}
	else
	{
		pPortHandle = pPortData->PortHandle;
		pPortName = pPortData->PortName;
		pWriteSection = pPortData->WriteSection;

		qemu_free(pPortData);
	}

    //fprintf(stderr, "postNtSecureConnectPort: PortHandle %08x, PortName %08x, WriteSection %08x\n", pPortHandle, pPortName, pWriteSection);

    // if succeed
    if(env->regs[R_EAX] == 0)
	{
		if(pWriteSection == 0)
			goto remove_bp;

		//if(!qebek_get_current_pid(env, &PID)) //system thread
		//	goto remove_bp;
		PID = env->cr[3];

		if(!qebek_read_ulong(env, pPortHandle, &PortHandle))
		{
			fprintf(stderr, "postNtSecureConnectPort: failed to read *PortHandle.\n");
			goto remove_bp;
		}

		if(!qebek_read_uword(env, pPortName, &name_length))
		{
			fprintf(stderr, "postNtSecureConnectPort: failed to read PortName->Length.\n");
			goto remove_bp;
		}

		if(name_length != 32)
			goto remove_bp;

		if(!qebek_read_ulong(env, pPortName + 4, &name_buffer))
		{
			fprintf(stderr, "postNtSecureConnectPort: failed to read PortName->Buffer.\n");
			goto remove_bp;
		}

		if(!qebek_read_raw(env, name_buffer, (unsigned char *)port_name, 32))
		{
			fprintf(stderr, "postNtSecureConnectPort: failed to read PortName->Buffer content.\n");
			goto remove_bp;
		}

		if(memcmp(port_name, target_name, 32))
			goto remove_bp;

		if(!qebek_read_ulong(env, pWriteSection + 16, &ViewBase))
		{
			fprintf(stderr, "postNtSecureConnectPort: failed to read WriteSection->ViewBase.\n");
			goto remove_bp;
		}

		if(!qebek_read_ulong(env, pWriteSection + 20, &TargetViewBase))
		{
			fprintf(stderr, "postNtSecureConnectPort: failed to read WriteSection->TargetViewBase.\n");
			goto remove_bp;
		}

		VirtualOffset = TargetViewBase - ViewBase;

		InsertCsrssPortHandle(PID, PortHandle, VirtualOffset);
	}

remove_bp:
    // remove return address
    bp_addr = env->eip;
    if(!qebek_bp_remove(bp_addr, env->cr[3], env->regs[R_EBP]))
    {
        fprintf(stderr, "postNtSecureConnectPort: failed to remove postcall interception.\n");
    }
}

void preNtClose(CPUX86State *env, void* user_data)
{
	uint32_t Handle, PID;

	//get handle from stack
	qebek_read_ulong(env, env->regs[R_ESP] + 4, &Handle);

	//if(qebek_get_current_pid(env, &PID))
	{
		PID = env->cr[3];
		RemoveCsrssPortHandle(PID, Handle);
		RemoveSocketEntry(PID, Handle);
	}
}

void preNtRequestWaitReplyPort(CPUX86State *env, void* user_data)
{
	uint32_t PortHandle, RequestMessage;
	target_ulong ret_addr, csrmsg_addr, opcode_addr;
	PNtRequestPortData pPortData;
	uint32_t PID, VirtualOffset, OpCode;

	//get port handle, request message address
	qebek_read_ulong(env, env->regs[R_ESP] + 4, &PortHandle);
	qebek_read_ulong(env, env->regs[R_ESP] + 2 * 4, &RequestMessage);

	//fprintf(stderr, "preNtRequestWaitReplyPort: PortHandle %08x, RequestMessage %08x\n", PortHandle, RequestMessage);
	
	if(RequestMessage == 0)
		return;

	//if(!qebek_get_current_pid(env, &PID))
	//	return;
	PID = env->cr[3];

	if(!IsCsrssPortHandle(PID, PortHandle))
		return;

	VirtualOffset = GetVirtualOffsetFromHandle(PID, PortHandle);
	csrmsg_addr = RequestMessage + 24;
	opcode_addr = csrmsg_addr + 4;

	//read opcode
	if(!qebek_read_ulong(env, opcode_addr, &OpCode))
	{
		fprintf(stderr, "preNtRequestWaitReplyPort: failed to read opcode: %08x\n", opcode_addr);
		return;
	}
	
	if(OpCode == OPCODE_WRITE_CONSOLE)
	{
		OnCsrWriteDataPre(env, RequestMessage, VirtualOffset);
	}
	else if(OpCode == OPCODE_READ_CONSOLE)
	{
		pPortData = (PNtRequestPortData)qemu_malloc(sizeof(NtRequestPortData));
		if(pPortData != NULL)
		{
			pPortData->Message = RequestMessage;
			pPortData->VirtualOffset = VirtualOffset;
		}

		// set return address, so the VM will break when returned
		qebek_read_ulong(env, env->regs[R_ESP], &ret_addr);
		if(!qebek_bp_add(ret_addr, env->cr[3], env->regs[R_EBP], postNtRequestWaitReplyPort, pPortData))
		{
			fprintf(stderr, "preNtRequestWaitReplyPort: failed to add postcall interception.\n");
		}
	}
}

void postNtRequestWaitReplyPort(CPUX86State *env, void* user_data)
{
	uint32_t PortHandle, RequestMessage, VirtualOffset, PID;
	target_ulong bp_addr;
	PNtRequestPortData pPortData = (PNtRequestPortData)user_data;

	if(pPortData == NULL)
	{
		//get port handle, request message address
		qebek_read_ulong(env, env->regs[R_ESP] - 3 * 4, &PortHandle);
		qebek_read_ulong(env, env->regs[R_ESP] - 2 * 4, &RequestMessage);

		//if(!qebek_get_current_pid(env, &PID))
		//	goto remove_bp;
		PID = env->cr[3];

		VirtualOffset = GetVirtualOffsetFromHandle(PID, PortHandle);
	}
	else
	{
		RequestMessage = pPortData->Message;
		VirtualOffset = pPortData->VirtualOffset;

		qemu_free(pPortData);
	}

	//fprintf(stderr, "postNtRequestWaitReplyPort: PortHandle %08x, RequestMessage %08x\n", PortHandle, RequestMessage);

	OnCsrReadDataPost(env, RequestMessage, VirtualOffset);

	// remove return address
    bp_addr = env->eip;
    if(!qebek_bp_remove(bp_addr, env->cr[3], env->regs[R_EBP]))
    {
        fprintf(stderr, "postNtRequestWaitReplyPort: failed to remove postcall interception.\n");
    }
}

void OnCsrWriteDataPre(CPUX86State *env, ULONG Message, ULONG VirtualOffset)
{
	uint32_t MessageBuffer, MessageBufferPtr, MessageBufferSize;
	uint8_t Unicode;
	uint32_t Offset, WriteStringPtr = 0;
	USHORT cbSize = 0;
	uint8_t *buffer;
	
	//get MessageBuffer, MessageBufferPtr, MessageBufferSize
	MessageBuffer =  Message + 24 + 16 + 8; // 0x30
	qebek_read_ulong(env, Message + 24 + 16 + 88, &MessageBufferPtr); // 0x80
	qebek_read_ulong(env, Message + 24 + 16 + 92, &MessageBufferSize); // 0x84
	qebek_read_byte(env, Message + 24 + 16 + 101, &Unicode); //0x8d

	//fprintf(stderr, "OnWriteDataPre: MessageBuffer %08x, MessageBufferPtr %08x, MessageBufferSize %08x, Unicode %d\n",
	//		MessageBuffer, MessageBufferPtr, MessageBufferSize, Unicode);

	if(MessageBuffer != MessageBufferPtr)
	{
		Offset = MessageBufferPtr - VirtualOffset;

		if(cpu_get_phys_page_debug(env, Offset) == -1)
			return;

		if(cpu_get_phys_page_debug(env, Offset + MessageBufferSize) == -1)
			return;

		WriteStringPtr = Offset;
		cbSize = (USHORT)MessageBufferSize;
	}
	else
	{
		WriteStringPtr = MessageBuffer;
		cbSize = (USHORT)(min(MessageBufferSize, CONSOLE_WRITE_INFO_MESSAGE_BUFFER_SIZE));
	}

	if(!WriteStringPtr) // bad data
		return;

	buffer = (uint8_t *)qemu_malloc(cbSize + 1);
	if(buffer == NULL)
	{
		fprintf(stderr, "OnCsrWriteDataPre: failed to allocate buffer.\n");
		return;
	}
	memset(buffer, 0, cbSize + 1);

	if(!qebek_read_raw(env, WriteStringPtr, buffer, cbSize))
	{
		fprintf(stderr, "OnCsrWriteDataPre: failed to read buffer: %x %x\n", WriteStringPtr, cbSize);
	}
	else
	{
		if(Unicode)
			UnicodeToAnsiString(buffer, &cbSize);
		// log
		qebek_log_data(env, SEBEK_TYPE_READ, buffer, cbSize);
	}

	qemu_free(buffer);
}

void OnCsrReadDataPost(CPUX86State *env, ULONG Message, ULONG VirtualOffset)
{
	uint32_t MessageBuffer, MessageBufferPtr, MessageBufferSize, NumberOfCharsToRead;
	uint8_t Unicode;
	uint32_t Offset, ReadStringPtr = 0;
	uint8_t *buffer;
	USHORT length;
	
	//get MessageBuffer, MessageBufferPtr, MessageBufferSize
	MessageBuffer = Message + 24 + 16 + 10; // 0x32
	qebek_read_ulong(env, Message + 24 + 16 + 92, &MessageBufferPtr); // 0x84
	qebek_read_ulong(env, Message + 24 + 16 + 96, &NumberOfCharsToRead); // 0x88
	qebek_read_ulong(env, Message + 24 + 16 + 100, &MessageBufferSize); // 0x8c
	qebek_read_byte(env, Message + 24 + 16 + 116, &Unicode); // 0x9c

	//fprintf(stderr, "OnReadDataPost: MessageBuffer %08x, MessageBufferPtr %08x, NumberOfCharsToRead %08x, MessageBufferSize %08x, Unicode %d\n",
	//		MessageBuffer, MessageBufferPtr, NumberOfCharsToRead, MessageBufferSize, Unicode);
	
	if(MessageBuffer != MessageBufferPtr)
	{
		Offset = MessageBufferPtr - VirtualOffset;

		if(cpu_get_phys_page_debug(env, Offset) == -1)
			return;

		if(cpu_get_phys_page_debug(env, Offset + MessageBufferSize) == -1)
			return;

		ReadStringPtr = Offset;
		length = (USHORT)NumberOfCharsToRead;
	}
	else
	{
		ReadStringPtr = MessageBuffer;
		length = (USHORT)(min(NumberOfCharsToRead, CONSOLE_READ_INFO_MESSAGE_BUFFER_SIZE));
	}

	if(!ReadStringPtr) // bad data
		return;

	buffer = (uint8_t *)qemu_malloc(length + 1);
	if(buffer == NULL)
	{
		fprintf(stderr, "OnCsrReadDataPost: failed to allocate buffer.\n");
		return;
	}
	memset(buffer, 0, length + 1);

	if(!qebek_read_raw(env, ReadStringPtr, buffer, length))
	{
		fprintf(stderr, "OnCsrReadDataPost: failed to read buffer: %x %x\n", ReadStringPtr, length);
	}
	else
	{
		if(Unicode)
			UnicodeToAnsiString(buffer, &length);
		// log
		qebek_log_data(env, SEBEK_TYPE_READ, buffer, length);
	}

	qemu_free(buffer);

}

void preNtCreateThread(CPUX86State *env, void* user_data)
{
	target_ulong ret_addr;

	//fprintf(stderr, "preNtCreateThread\n");

	// set return address, so the VM will break when returned
    qebek_read_ulong(env, env->regs[R_ESP], &ret_addr);
    if(!qebek_bp_add(ret_addr, env->cr[3], env->regs[R_EBP], postNtCreateThread, NULL))
    {
        fprintf(stderr, "preNtCreateThread: failed to add postcall interception.\n");
    }
	
}

void postNtCreateThread(CPUX86State *env, void* user_data)
{
	target_ulong bp_addr;

	//fprintf(stderr, "postNtCreateThread\n");

	if(env->regs[R_EAX] == 0)
	{
		// log
		//qebek_log_data(env, SEBEK_TYPE_READ, NULL, 0);
	}

	// remove return address
    bp_addr = env->eip;
    if(!qebek_bp_remove(bp_addr, env->cr[3], env->regs[R_EBP]))
    {
        fprintf(stderr, "postNtCreateThread: failed to remove postcall interception.\n");
    }
}

bool UnicodeToAnsiString(uint8_t *buffer, uint16_t *length)
{
	return DummyUnicodeToAnsiString(buffer, length);
}

bool DummyUnicodeToAnsiString(uint8_t *buffer, uint16_t *length)
{
	uint16_t i,j;

	for(i = 0, j = 0; i < *length; i += 2, j++)
	{
		buffer[j] = buffer[i];
	}

	*length /= 2;

	return True;
}
