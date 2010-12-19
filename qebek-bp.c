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

#include <string.h>
#include "qemu-common.h"
#include "qebek-bp.h"

static qebek_bp_slot** qebek_bpt = NULL;

bool qebek_bpt_init(void)
{
	qebek_bpt = qemu_malloc(QEBEK_BP_SIZE);
	if(!qebek_bpt)
	{
		fprintf(stderr, "qebek_bpt_init: failed to allocate break point table.\n");

		return False;
	}
	
	memset(qebek_bpt, 0, QEBEK_BP_SIZE);

	return True;
}

void qebek_bpt_free(void)
{
	int i;
	qebek_bp_slot *slot1, *slot2;

	if(qebek_bpt)
		return;

	for(i = 0; i < QEBEK_BP_MAX; i++)
	{
		for(slot1 = qebek_bpt[i]; slot1 != NULL;)
		{
			slot2 = slot1;
			slot1 = slot1->next;
			qemu_free(slot2);
		}
	}

	qemu_free(qebek_bpt);
}

bool qebek_bp_add(target_ulong address, target_ulong pid, target_ulong stack_id, qebek_cb_func cb_func, void* user_data)
{
	qebek_bp_slot* bp_slot;
	uint32_t hash;

	if(qebek_bpt == NULL)
		return False;

	hash = QEBEK_BP_HASH(address);
	for(bp_slot = qebek_bpt[hash]; bp_slot != NULL; bp_slot = bp_slot->next)
	{
		if(bp_slot->breakpoint == 0)
			break;
	}
	
	if(bp_slot == NULL)
	{
		bp_slot = qemu_malloc(sizeof(qebek_bp_slot));
		if(bp_slot == NULL)
		{
			fprintf(stderr, "qebek_bp_add: failed to allocate break point.\n");

			return False;
		}
		bp_slot->next = qebek_bpt[hash];
		qebek_bpt[hash] = bp_slot;
	}

	bp_slot->breakpoint = address;
	bp_slot->pid = pid;
	bp_slot->stack_id = stack_id;
	bp_slot->cb_func = cb_func;
	bp_slot->user_data = user_data;

	return True;
}

bool qebek_bp_remove(target_ulong address, target_ulong pid, target_ulong stack_id)
{
	qebek_bp_slot *bp_slot, *bp_next;
	uint32_t hash;

	if(qebek_bpt == NULL)
		return False;

	hash = QEBEK_BP_HASH(address);
	for(bp_slot = qebek_bpt[hash]; bp_slot != NULL; bp_slot = bp_slot->next)
	{
		if(bp_slot->breakpoint == address && bp_slot->pid == pid && bp_slot->stack_id == stack_id)
		{
			bp_next = bp_slot->next;
			
			/* lazy delete, avoid frequent memory alloc and free
			   caller has to free user_data manually */
			memset(bp_slot, 0, sizeof(qebek_bp_slot));
			bp_slot->next = bp_next;

			return True;
		}
	}

	return False;
}

qebek_bp_slot* qebek_bp_check(target_ulong address, target_ulong pid, target_ulong stack_id)
{
	qebek_bp_slot* bp_slot;
	uint32_t hash;

	if(qebek_bpt == NULL)
		return NULL;

	if(address == 0) // assume none zero break point
		return NULL;

	hash = QEBEK_BP_HASH(address);
	for(bp_slot = qebek_bpt[hash]; bp_slot != NULL; bp_slot = bp_slot->next)
	{
		if(bp_slot->breakpoint == address && 
				(bp_slot->pid == 0 || bp_slot->pid == pid) &&
				(bp_slot->stack_id == 0 || bp_slot->stack_id == stack_id)
		  )
			return bp_slot;
	}

	return NULL;
}

