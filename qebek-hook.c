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

#include <stdio.h>
#include "qebek-common.h"
#include "qebek-os.h"
#include "qebek-bp.h"
#include "qebek-hook.h"
#include "qebek-nt-console.h"
#include "qebek-nt-network.h"

int qebek_syscall_init = 0;

void qebek_hook_syscall(CPUState *env)
{
#if defined(TARGET_I386)
    target_ulong pkthread, psdt, pssdt; //structure pointer
	target_ulong kthread, sdt, ssdt; //virtual address
#endif

	switch(qebek_os_major)
	{
	case QEBEK_OS_windows:

#if defined(TARGET_I386)

        pkthread = 0xffdff000 + 0x124; //FIXME
        //fprintf(stderr, "qebek_hook_syscall: pkthread %08x\n", pkthread);

		if(!qebek_read_ulong(env, pkthread, &kthread))
		{
			fprintf(stderr, "qebek_hook_syscall: failed to read kthread\n");
			return;
		}
		
		psdt = kthread + 0xe0;
		if(!qebek_read_ulong(env, psdt, &sdt))
		{
			fprintf(stderr, "qebek_hook_syscall: failed to read SDT\n");
			return;
		}
		
		pssdt = sdt;
		if(!qebek_read_ulong(env, pssdt, &ssdt))
		{
			fprintf(stderr, "qebek_hook_syscall: failed to read SSDT\n");
			return;
		}
#elif defined(TARGET_X86_64)
#endif

#if defined(TARGET_I386) || defined(TARGET_X86_64)
		switch(qebek_os_minor)
		{
		case QEBEK_OS_winxp:
			index_NtRequestWaitReplyPort = 0x0c8;
			index_NtSecureConnectPort = 0x0d2;
			index_NtClose = 0x019;
			index_NtReadFile = 0x0b7;
			index_NtWriteFile = 0x112;

			index_NtDeviceIoControlFile = 0x042;
			index_NtWaitForSingleObject = 0x10f;

			index_NtCreateThread = 0x035;
			break;

		case QEBEK_OS_win2k:
			index_NtRequestWaitReplyPort = 0x0b0;
			index_NtSecureConnectPort = 0x0b8;
			index_NtClose = 0x018;
			index_NtReadFile = 0x0a1;
			index_NtWriteFile = 0x0ed;

			index_NtDeviceIoControlFile = 0x038;
			index_NtWaitForSingleObject = 0x0ea;

			index_NtCreateThread = 0x02e;
			break;

		case QEBEK_OS_win2k3:
			index_NtRequestWaitReplyPort = 0x0d0;
			index_NtSecureConnectPort = 0x0da;
			index_NtClose = 0x01b;
			index_NtReadFile = 0x0bf;
			index_NtWriteFile = 0x11c;

			index_NtDeviceIoControlFile = 0x045;
			index_NtWaitForSingleObject = 0x119;

			index_NtCreateThread = 0x037;
			break;

		case QEBEK_OS_vista:
		case QEBEK_OS_win2k8:
			index_NtRequestWaitReplyPort = 0x110;
			index_NtSecureConnectPort = 0x11f;
			index_NtClose = 0x02f;
			index_NtReadFile = 0x0ff;
			index_NtWriteFile = 0x164;

			index_NtDeviceIoControlFile = 0x07e;
			index_NtWaitForSingleObject = 0x161;

			index_NtCreateThread = 0x181; //NtCreateThreadEx in fact
			break;

		case QEBEK_OS_win7:
			index_NtRequestWaitReplyPort = 0x12b;
			index_NtSecureConnectPort = 0x138;
			index_NtClose = 0x032;
			index_NtReadFile = 0x111;
			index_NtWriteFile = 0x18c;

			index_NtDeviceIoControlFile = 0x06b;
			index_NtWaitForSingleObject = 0x187;

			index_NtCreateThread = 0x058; //NtCreateThreadEx in fact
			break;

		default:
			break;
		}

		// ConsoleSpy
		//
		if(!InitConsoleSpy())
		{
			fprintf(stderr, "qebek_hook_syscall: failed to initialize windows console spy.\n");
			return;
		}
	
		qebek_read_ulong(env, ssdt + index_NtRequestWaitReplyPort * 4, &NtRequestWaitReplyPort);
		qebek_read_ulong(env, ssdt + index_NtSecureConnectPort * 4, &NtSecureConnectPort);
		qebek_read_ulong(env, ssdt + index_NtClose * 4, &NtClose);
		qebek_read_ulong(env, ssdt + index_NtReadFile * 4, &NtReadFile);
		qebek_read_ulong(env, ssdt + index_NtWriteFile * 4, &NtWriteFile);
		//fprintf(stderr, "NtWriteFile: %x\n", NtWriteFile);

		qebek_read_ulong(env, ssdt + index_NtCreateThread * 4, &NtCreateThread);

		if(!qebek_bp_add(NtRequestWaitReplyPort, 0, 0, preNtRequestWaitReplyPort, NULL))
		{
			fprintf(stderr, "qebek_hook_syscall: failed to insert break point for NtRequestWaitReplyPort\n");
			return;
		}
		if(!qebek_bp_add(NtSecureConnectPort, 0, 0, preNtSecureConnectPort, NULL))
		{
			fprintf(stderr, "qebek_hook_syscall: failed to insert break point for NtSecureConnectPort\n");
			return;
		}
		if(!qebek_bp_add(NtClose, 0, 0, preNtClose, NULL))
		{
			fprintf(stderr, "qebek_hook_syscall: failed to insert break point for NtClose\n");
			return;
		}
		if(!qebek_bp_add(NtReadFile, 0, 0, preNtReadFile, NULL))
		{
			fprintf(stderr, "qebek_hook_syscall: failed to insert break point for NtReadFile\n");
			return;
		}
		if(!qebek_bp_add(NtWriteFile, 0, 0, preNtWriteFile, NULL))
		{
			fprintf(stderr, "qebek_hook_syscall: failed to insert break point for NtWriteFile\n");
			return;
		}

		if(!qebek_bp_add(NtCreateThread, 0, 0, preNtCreateThread, NULL))
		{
			fprintf(stderr, "qebek_hook_syscall: failed to insert break point for NtCreateThread\n");
			return;
		}

		// network
		//
		if(!InitNetwork())
		{
			fprintf(stderr, "qebek_hook_syscall: failed to initialize network spy.\n");
			return;
		}
		
		qebek_read_ulong(env, ssdt + index_NtDeviceIoControlFile * 4, &NtDeviceIoControlFile);
		qebek_read_ulong(env, ssdt + index_NtWaitForSingleObject * 4, &NtWaitForSingleObject);
		
		if(!qebek_bp_add(NtDeviceIoControlFile, 0, 0, preNtDeviceIoControlFile, NULL))
		{
			fprintf(stderr, "qebek_hook_syscall: failed to insert break point for NtDeviceIoControlFile\n");
			return;
		}
#endif //TARGET_I386 || TARGET_X86_64

		break;

	case QEBEK_OS_linux:
		break;

	default:
		break;
	}

	qebek_syscall_init = True;
}

int qebek_check_target(CPUState *env, target_ulong eip)
{
	if(unlikely(eip == 0))
		return 0;

	/*
	// NtReadFile pre call
	if(eip == NtReadFile)
	{
		// get file handle, buffer & buffer size from stack
		qebek_read_ulong(env, env->regs[R_ESP] + 4, &ReadHandle);
		qebek_read_ulong(env, env->regs[R_ESP] + 4 * 6, &ReadBuffer);
		qebek_read_ulong(env, env->regs[R_ESP] + 4 * 7, &ReadSize);

		fprintf(stderr, "Read FileHandle %08x, Buffer %08x, Size %08x\n", ReadHandle, ReadBuffer, ReadSize);
		
		// set return address, so the VM will break when returned
		qebek_read_ulong(env, env->regs[R_ESP], &NtReadFilePost);
	}
	// NtReadFile post call
	else if(eip == NtReadFilePost)
	{
		fprintf(stderr, "ReadPost\n");
		// if succeed
		if(env->regs[R_EAX] == 0)
			OnNtReadWriteFile(env, ReadHandle, ReadBuffer, ReadSize);

		NtReadFilePost = 0;
	}*/
	
	qebek_bp_slot* bp_slot = NULL;
	target_ulong pid = 0;
	target_ulong stack_id = 0;

#if defined(TARGET_I386) || defined(TARGET_X86_64)
	pid = env->cr[3];
	stack_id = env->regs[R_EBP];
#endif
	
	if((bp_slot = qebek_bp_check(eip, pid, stack_id)) == NULL)
		return 0;

	bp_slot->cb_func(env, bp_slot->user_data);

	return 1; //break point hit
}
