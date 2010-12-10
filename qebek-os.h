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

#ifndef QEBEK_OS_H
#define QEBEK_OS_H

typedef enum qebek_os_major_t {
	QEBEK_OS_windows,
	QEBEK_OS_linux,
}qebek_os_major_t;

typedef enum qebek_os_minor_t {
	/* windows nt series */
	QEBEK_OS_win2k,
	QEBEK_OS_winxp,
	QEBEK_OS_win2k3,
	QEBEK_OS_vista,
	QEBEK_OS_win2k8,
	QEBEK_OS_win7,

	/* linux series */
}qebek_os_minor_t;

qebek_os_major_t qebek_os_major;
qebek_os_minor_t qebek_os_minor;

#endif
