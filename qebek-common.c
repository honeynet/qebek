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

int qebek_read_ulong(CPUX86State *env, target_ulong address, target_ulong *value)
{
	target_phys_addr_t phys_addr;

	phys_addr = cpu_get_phys_page_debug(env, address);
	if(phys_addr == -1)
		return 0;

	*value = ldl_phys((phys_addr & TARGET_PAGE_MASK) | (address & ~TARGET_PAGE_MASK));
	return 1;
}


