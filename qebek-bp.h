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

#ifndef QEBEK_BP_H
#define QEBEK_BP_H
#include "cpu.h"
#include "qebek-common.h"

typedef void (*qebek_cb_func)(CPUX86State *env, void* user_data);
//enum qebek_bp_type
//{
//	QEBEK_RECALL,
//	QEBEK_POSTCALL
//};

typedef struct qebek_bp_slot
{
	struct qebek_bp_slot *next;

	target_ulong breakpoint; //break point virtual address
	target_ulong cr3; //set if want to break for certain process
	target_ulong ebp; //set if want to break for certain thread

	qebek_cb_func cb_func; //callback function
	void* user_data; //callback data

	bool enable;
}qebek_bp_slot, *pqbek_bp_slot;

#define QEBEK_BP_MAX 0x1000
#define QEBEK_BP_HASH(X) ((X >> 4) & (QEBEK_BP_MAX - 1))

bool qebek_bpt_init();
void qebek_bpt_free();
qebek_bp_slot* qebek_bp_check(target_ulong address, target_ulong cr3, target_ulong ebp);
bool qebek_bp_add(target_ulong address, target_ulong cr3, target_ulong ebp, qebek_cb_func cb_func, void* user_data);
bool qebek_bp_remove(target_ulong address, target_ulong cr3, target_ulong ebp);

#endif
