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

bool qebek_read_ulong(CPUX86State *env, target_ulong address, target_ulong *value)
{
	target_phys_addr_t phys_addr;

	phys_addr = cpu_get_phys_page_debug(env, address);
	if(phys_addr == -1)
		return False;

	*value = ldl_phys((phys_addr & TARGET_PAGE_MASK) | (address & ~TARGET_PAGE_MASK));
	return True;
}

bool qebek_read_uword(CPUX86State *env, target_ulong address, target_ulong *value)
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
	//log data
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
		}

		break;

	default:
		break;
	}

	return True;
}
