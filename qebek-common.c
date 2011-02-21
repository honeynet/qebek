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
#include "cpu-common.h"
#include "cpu.h"
#include "targphys.h"
#include <netinet/in.h>
#include <sys/time.h>
#include "qebek-common.h"
#include "qebek-os.h"

uint32_t qebek_g_ip;
uint32_t qebek_g_magic;
 
qebek_os_major_t qebek_os_major;
qebek_os_minor_t qebek_os_minor;

bool qebek_read_ulong(CPUState *env, target_ulong address, target_ulong *value)
{
	target_phys_addr_t phys_addr;

	phys_addr = cpu_get_phys_page_debug(env, address);
	if(phys_addr == -1)
		return False;

	*value = ldl_phys((phys_addr & TARGET_PAGE_MASK) | (address & ~TARGET_PAGE_MASK));
	return True;
}

bool qebek_read_uword(CPUState *env, target_ulong address, uint16_t *value)
{
	target_phys_addr_t phys_addr;

	phys_addr = cpu_get_phys_page_debug(env, address);
	if(phys_addr == -1)
		return False;

	*value = lduw_phys((phys_addr & TARGET_PAGE_MASK) | (address & ~TARGET_PAGE_MASK));
	return True;
}

bool qebek_read_byte(CPUState *env, target_ulong address, uint8_t *value)
{
    target_phys_addr_t phys_addr;

    phys_addr = cpu_get_phys_page_debug(env, address);
    if(phys_addr == -1)
        return False;

    *value = ldub_phys((phys_addr & TARGET_PAGE_MASK) | (address & ~TARGET_PAGE_MASK));
    return True;
}

bool qebek_read_raw(CPUState *env, target_ulong address, unsigned char* buffer, int len)
{
	target_phys_addr_t phys_addr;

	phys_addr = cpu_get_phys_page_debug(env, address);
	if(phys_addr == -1)
		return False;

	cpu_physical_memory_read((phys_addr & TARGET_PAGE_MASK) | (address & ~TARGET_PAGE_MASK), buffer, len);
	return True;
}

void qebek_log_data(CPUState *env, uint16_t type, uint8_t *data, uint32_t len)
{
	static int counter;
	struct timeval tv;
	struct sebek_hdr sbk_hdr;
	proc_info_t proc_info;

	gettimeofday(&tv, NULL);

	//get process information
	if(!qebek_get_proc_info(env, &proc_info))
		return;

	memset(&sbk_hdr, 0, sizeof(sbk_hdr));
	
	sbk_hdr.magic = htonl(qebek_g_magic);
	sbk_hdr.version = htons(SEBEK_PROTOCOL_VER);
	sbk_hdr.type = htons(type);

	sbk_hdr.counter = htonl(counter++);
	sbk_hdr.time_sec = htonl(tv.tv_sec);
	sbk_hdr.time_usec = htonl(tv.tv_usec);

	sbk_hdr.parent_pid = htonl(proc_info.ppid);
	sbk_hdr.pid = htonl(proc_info.pid);

	memcpy(sbk_hdr.com, proc_info.pname, SEBEK_HEADER_COMMAND_LEN);
	sbk_hdr.length = htonl(len);

	fwrite(&tv.tv_sec, 4, 1, stdout); // write fake pcap sec
	fwrite(&tv.tv_usec, 4, 1, stdout); // write fake pcap usec
	fwrite(&qebek_g_ip, 4, 1, stdout); // write fake ip
	fwrite(&sbk_hdr, sizeof(sbk_hdr), 1, stdout); // write sebek header
	if(data)
		fwrite(data, len, 1, stdout); // write sebek data
	fflush(stdout);
}

bool qebek_get_current_pid(CPUState *env, uint32_t *pid)
{
#if defined(TARGET_I386)
	target_ulong pkthread = env->segs[R_FS].base + 124;
#endif
	target_ulong peprocess, pid_addr;
	target_ulong kthread, eprocess;
	*pid = 0xffffffff;

	switch(qebek_os_major)
	{
	case QEBEK_OS_windows:

#if defined(TARGET_I386)
		if(!qebek_read_ulong(env, pkthread, &kthread))
		{
			fprintf(stderr,"qebek_get_current_pid: failed to read KTHREAD address.\n");
			return False;
		}

		peprocess = kthread + 0x44;
		if(!qebek_read_ulong(env, peprocess, &eprocess))
		{
			fprintf(stderr,"qebek_get_current_pid: failed to read EPROCESS address, pointer %08X.\n", peprocess);
			return False;
		}

		if(eprocess == 0) //system thread, belongs to no process
			return False;

		pid_addr = eprocess + 0x84;
		if(!qebek_read_ulong(env, pid_addr, pid))
		{
			fprintf(stderr,"qebek_get_current_pid: failed to read PID, pointer %08X.\n", pid_addr);
			return False;
		}
#endif
		break;

	case QEBEK_OS_linux:
		break;

	default:
		break;
	}

	return True;
}

bool qebek_get_proc_info(CPUState *env, proc_info_t *proc_info)
{
#if defined(TARGET_I386)
	target_ulong pkthread; 
	target_ulong peprocess, pid_addr, ppid_addr, pname_addr;
	target_ulong kthread, eprocess;
	uint32_t pname_offset;
#endif

	switch(qebek_os_major)
	{
	case QEBEK_OS_windows:

#if defined(TARGET_I386)
        
        /* This should always works as this function is always call from kernel mode */
        pkthread = env->segs[R_FS].base + 0x124;
        //fprintf(stderr,"qebek_get_proc_info: pkthread %08x\n", pkthread);

		if(!qebek_read_ulong(env, pkthread, &kthread))
		{
			fprintf(stderr,"qebek_get_proc_info: failed to read KTHREAD address.\n");
			return False;
		}

		peprocess = kthread + 0x44;
		if(!qebek_read_ulong(env, peprocess, &eprocess))
		{
			fprintf(stderr,"qebek_get_proc_info: failed to read EPROCESS address, pointer %08X.\n", peprocess);
			return False;
		}

		if(eprocess == 0) //system thread, belongs to no process
			return False;

		pid_addr = eprocess + 0x84;
		if(!qebek_read_ulong(env, pid_addr, &proc_info->pid))
		{
			fprintf(stderr,"qebek_get_proc_info: failed to read PID, pointer %08X.\n", pid_addr);
			return False;
		}

		ppid_addr = eprocess + 0x14c;
		if(!qebek_read_ulong(env, ppid_addr, &proc_info->ppid))
		{
			fprintf(stderr,"qebek_get_proc_info: failed to read PPID, pointer %08X.\n", ppid_addr);
			return False;
		}

		switch(qebek_os_minor)
		{
		case QEBEK_OS_winxp:
			pname_offset = 0x174;
			break;

		default:
			return False;
		}
		
		pname_addr = eprocess + pname_offset;
		memset(proc_info->pname, 0, PROCNAMELEN+1);
		if(!qebek_read_raw(env, pname_addr, (unsigned char *)proc_info->pname, PROCNAMELEN))
		{
			fprintf(stderr,"qebek_get_proc_info: failed to read PNAME, pointer %08X.\n", pname_addr);
			return False;
		}
#endif

		break;

	case QEBEK_OS_linux:
		break;

	default:
		break;
	}

	return True;
}
