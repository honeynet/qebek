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
#include "qebek-console.h"

BOOLEAN IsHandleStd(CPUX86State *env, CONST HANDLE Handle)
{
	target_ulong pkthread = 0xffdff124, pteb, ppeb, pproc_param;
	target_ulong kthread, teb, peb, proc_param;
	uint32_t stdin_handle, stdout_handle, stderr_handle;
		
	// get KPCR.KPRCB->KTHREAD->TEB->PEB->ProcessParameters
	if(!qebek_read_ulong(env, pkthread, &kthread))
	{
		qemu_printf("LogIfStdHandle: failed to read kthread\n");
		return False;
	}

	pteb = kthread + 0x20;
	if(!qebek_read_ulong(env, pteb, &teb))
	{
		qemu_printf("LogIfStdHandle: failed to read teb\n");
		return False;
	}	

	ppeb = teb + 0x30;
	if(!qebek_read_ulong(env, ppeb, &peb))
    {
        qemu_printf("LogIfStdHandle: failed to read peb\n");
        return False;
    }

	pproc_param = peb + 0x10;
	if(!qebek_read_ulong(env, pproc_param, &proc_param))
    {
        qemu_printf("LogIfStdHandle: failed to read process_parameters\n");
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
		qemu_printf("LogIfStdHandle: std handle\n");
		return True;
	}

	return False;
}

VOID OnNtReadWriteFile(CPUX86State *env, HANDLE Handle, ULONG Buffer, ULONG BufferSize)
{
	uint8_t *buffer;

	if(!IsHandleStd(env, Handle))
		return;
	
	buffer = qemu_malloc(BufferSize);
	if(buffer == NULL)
	{
		qemu_printf("OnNtReadWriteFile: failed to alloc buffer\n");
		return;
	}

	if(!qebek_read_raw(env, Buffer, buffer, BufferSize))
	{
		qemu_printf("OnNtReadWriteFile: failed to read buffer: %x %x\n", Buffer, BufferSize);
	}
	else
	{
		// log
		//qebek_log_data(env, SEBEK_TYPE_READ, buffer, BufferSize);
	}

	qemu_free(buffer);
}
