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

#include <stdio.h>
#include "qebek-common.h"
#include "qebek-os.h"
#include "qebek-op.h"
#include "qebek-bp.h"
#include "qebek-console.h"


void qebek_get_service_address(CPUX86State *env)
{
	target_ulong pkthread = 0xffdff124, psdt, pssdt; //structure pointer
	target_ulong kthread, sdt, ssdt; //virtual address

	if(qebek_service_init)
		return;
	
	switch(qebek_os_major)
	{
	
	case QEBEK_OS_windows:

		if(!qebek_read_ulong(env, pkthread, &kthread))
		{
			qemu_printf("qebek_get_service_address: failed to read kthread\n");
			return;
		}
		
		psdt = kthread + 0xe0;
		if(!qebek_read_ulong(env, psdt, &sdt))
		{
			qemu_printf("qebek_get_service_address: failed to read SDT\n");
			return;
		}
		
		pssdt = sdt;
		if(!qebek_read_ulong(env, pssdt, &ssdt))
		{
			qemu_printf("qebek_get_service_address: failed to read SSDT\n");
			return;
		}

		switch(qebek_os_minor)
		{
		case QEBEK_OS_winxp:
			index_NtRequestWaitReplyPort = 0x0c5;
			index_NtSecureConnectPort = 0x0d2;
			index_NtClose = 0x019;
			index_NtReadFile = 0x0b7;
			index_NtWriteFile = 0x112;
			break;
		default:
			break;
		}
	
		qebek_read_ulong(env, ssdt + index_NtRequestWaitReplyPort * 4, &NtRequestWaitReplyPort);
		qebek_read_ulong(env, ssdt + index_NtSecureConnectPort * 4, &NtSecureConnectPort);
		qebek_read_ulong(env, ssdt + index_NtClose * 4, &NtClose);
		qebek_read_ulong(env, ssdt + index_NtReadFile * 4, &NtReadFile);
		qebek_read_ulong(env, ssdt + index_NtWriteFile * 4, &NtWriteFile);
		qemu_printf("NtWriteFile: %x\n", NtWriteFile);

		/*if(!qebek_bp_add(NtRequestWaitReplyPort, preNtRequestWaitReplyPort, NULL))
		{
			qemu_printf("qebek_get_service_address: failed to insert break point for NtRequestWaitReplyPort\n");
			return;
		}
        if(!qebek_bp_add(NtSecureConnectPort, preNtSecureConnectPort, NULL))
        {
            qemu_printf("qebek_get_service_address: failed to insert break point for NtSecureConnectPort\n");
            return;
        }
        if(!qebek_bp_add(NtClose, preNtClose, NULL))
        {
            qemu_printf("qebek_get_service_address: failed to insert break point for NtClose\n");
            return;
        }*/
        if(!qebek_bp_add(NtReadFile, preNtReadFile, NULL))
        {
            qemu_printf("qebek_get_service_address: failed to insert break point for NtReadFile\n");
            return;
        }
        if(!qebek_bp_add(NtWriteFile, preNtWriteFile, NULL))
        {
            qemu_printf("qebek_get_service_address: failed to insert break point for NtWriteFile\n");
            return;
        }

		break;
		
	default:
		break;
	}

	qebek_service_init = 1;
}

void qebek_check_target(CPUX86State *env, target_ulong new_eip)
{
	target_ulong eip = new_eip + env->segs[R_CS].base;
	qebek_bp_slot* bp_slot = NULL;	

	if(eip == 0)
		return;

	/*
	// NtReadFile pre call
	if(eip == NtReadFile)
	{
		// get file handle, buffer & buffer size from stack
		qebek_read_ulong(env, env->regs[R_ESP] + 4, &ReadHandle);
		qebek_read_ulong(env, env->regs[R_ESP] + 4 * 6, &ReadBuffer);
		qebek_read_ulong(env, env->regs[R_ESP] + 4 * 7, &ReadSize);

		qemu_printf("Read FileHandle %08x, Buffer %08x, Size %08x\n", ReadHandle, ReadBuffer, ReadSize);
		
		// set return address, so the VM will break when returned
		qebek_read_ulong(env, env->regs[R_ESP], &NtReadFilePost);
	}
	// NtReadFile post call
	else if(eip == NtReadFilePost)
	{
		qemu_printf("ReadPost\n");
		// if succeed
		if(env->regs[R_EAX] == 0)
			OnNtReadWriteFile(env, ReadHandle, ReadBuffer, ReadSize);

		NtReadFilePost = 0;
	}*/

	if((bp_slot = qebek_bp_check(eip)) == NULL)
		return;

	bp_slot->cb_func(env, bp_slot->user_data);
}
