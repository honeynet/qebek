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
#include "qebek-common.h"
#include "qebek-os.h"

bool qebek_read_ulong(CPUX86State *env, target_ulong address, uint32_t *value)
{
	target_phys_addr_t phys_addr;

	phys_addr = cpu_get_phys_page_debug(env, address);
	if(phys_addr == -1)
		return False;

	*value = ldl_phys((phys_addr & TARGET_PAGE_MASK) | (address & ~TARGET_PAGE_MASK));
	return True;
}

bool qebek_read_uword(CPUX86State *env, target_ulong address, uint16_t *value)
{
	target_phys_addr_t phys_addr;

	phys_addr = cpu_get_phys_page_debug(env, address);
	if(phys_addr == -1)
		return False;

	*value = lduw_phys((phys_addr & TARGET_PAGE_MASK) | (address & ~TARGET_PAGE_MASK));
	return True;
}

bool qebek_read_raw(CPUX86State *env, target_ulong address, uint8_t* buffer, int len)
{
	target_phys_addr_t phys_addr;

	phys_addr = cpu_get_phys_page_debug(env, address);
	if(phys_addr == -1)
		return False;

	cpu_physical_memory_read((phys_addr & TARGET_PAGE_MASK) | (address & ~TARGET_PAGE_MASK), buffer, len);
	return True;
}

void qebek_log_data(CPUX86State *env, uint16_t type, uint8_t *data, uint32_t len)
{
	//get process information
	proc_info_t proc_info;

	qebek_get_proc_info(env, &proc_info);
}

bool qebek_get_current_pid(CPUX86State *env, uint32_t *pid)
{
	target_ulong pkthread = 0xffdff124, peprocess, pid_addr;
	target_ulong kthread, eprocess;
	*pid = 0xffffffff;

	switch(qebek_os_major)
	{
	case QEBEK_OS_windows:
		if(!qebek_read_ulong(env, pkthread, &kthread))
		{
			qemu_printf("qebek_get_current_pid: failed to read KTHREAD address.\n");
			return False;
		}

		peprocess = pkthread + 0x44;
		if(!qebek_read_ulong(env, peprocess, &eprocess))
		{
			qemu_printf("qebek_get_current_pid: failed to read EPROCESS address, pointer %08X.\n", peprocess);
			return False;
		}

		if(eprocess == 0) //system thread, belongs to no process
			return False;

		pid_addr = eprocess + 0x84;
		if(!qebek_read_ulong(env, pid_addr, pid))
		{
			qemu_printf("qebek_get_current_pid: failed to read PID, pointer %08X.\n", pid_addr);
			return False;
		}

		break;

	default:
		break;
	}

	return True;
}

bool qebek_get_proc_info(CPUX86State *env, proc_info_t *proc_info)
{
	target_ulong pkthread = 0xffdff124, peprocess, pid_addr, ppid_addr, pname_addr;
	target_ulong kthread, eprocess, pname;
	uint32_t pname_offset;

	switch(qebek_os_major)
	{
	case QEBEK_OS_windows:
		if(!qebek_read_ulong(env, pkthread, &kthread))
		{
			qemu_printf("qebek_get_proc_info: failed to read KTHREAD address.\n");
			return False;
		}

		peprocess = pkthread + 0x44;
		if(!qebek_read_ulong(env, peprocess, &eprocess))
		{
			qemu_printf("qebek_get_proc_info: failed to read EPROCESS address, pointer %08X.\n", peprocess);
			return False;
		}

		if(eprocess == 0) //system thread, belongs to no process
			return False;

		pid_addr = eprocess + 0x84;
		if(!qebek_read_ulong(env, pid_addr, &proc_info->pid))
		{
			qemu_printf("qebek_get_proc_info: failed to read PID, pointer %08X.\n", pid_addr);
			return False;
		}

		ppid_addr = eprocess + 0x14c;
		if(!qebek_read_ulong(env, ppid_addr, &proc_info->ppid))
		{
			qemu_printf("qebek_get_proc_info: failed to read PPID, pointer %08X.\n", ppid_addr);
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
		if(!qebek_read_raw(env, pname_addr, proc_info->pname, PROCNAMELEN))
		{
			qemu_printf("qebek_get_proc_info: failed to read PNAME, pointer %08X.\n", pname_addr);
			return False;
		}
		proc_info->pname[PROCNAMELEN] = '\0';

		break;

	default:
		break;
	}

	return True;
}
