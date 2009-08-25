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

#ifndef QEBEK_COMMON_H
#define QEBEK_COMMON_H
#include "cpu.h"

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef VOID
#define VOID void
#endif

typedef void *PVOID;

#ifndef CONST
#define CONST const
#endif

typedef unsigned char BOOLEAN, bool;
typedef target_ulong ULONG;
typedef target_ulong HANDLE;
typedef unsigned short USHORT;
typedef unsigned int UINT;
typedef unsigned char UCHAR;

#ifndef False
#define False 0
#endif

#ifndef True
#define True 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef PROCNAMELEN
#define PROCNAMELEN 20
#endif

#define SEBEK_MAGIC   208 // this is in network order. 0xD0D0D000 in host order on x86
#define SEBEK_PROTOCOL_VER 3

#define SYS_SOCKET      1               /* sys_socket(2)                */
#define SYS_BIND        2               /* sys_bind(2)                  */
#define SYS_CONNECT     3               /* sys_connect(2)               */
#define SYS_LISTEN      4               /* sys_listen(2)                */
#define SYS_ACCEPT      5               /* sys_accept(2)                */

#define SYS_SENDTO      11              /* sys_sendto(2)                */
#define SYS_RECVFROM    12              /* sys_recvfrom(2)              */
#define SYS_SENDMSG     16              /* sys_sendmsg(2)               */
#define SYS_RECVMSG     17              /* sys_recvmsg(2)               */

#ifndef IPPROTO_IP
#define IPPROTO_IP              0               /* dummy for IP */
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP            1               /* control message protocol */
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP             6               /* tcp */
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP             17              /* user datagram protocol */
#endif

#define SEBEK_HEADER_COMMAND_LEN 12
#define SEBEK_HEADER_WINDOWTITLE_LEN 32
#define SEBEK_HEADER_USERNAME_LEN 12

#define SEBEK_TYPE_READ 0
#define SEBEK_TYPE_WRITE 1
#define SEBEK_TYPE_SOCKET 2
#define SEBEK_TYPE_OPEN 3

uint32_t qebek_g_ip;
uint32_t qebek_g_magic;

typedef struct sebek_hdr{
  uint32_t  magic		__attribute__((packed));
  uint16_t  version		__attribute__((packed));
  uint16_t  type		__attribute__((packed));
  uint32_t  counter		__attribute__((packed));
  uint32_t  time_sec	__attribute__((packed));
  uint32_t  time_usec	__attribute__((packed));
  uint32_t  parent_pid	__attribute__((packed));
  uint32_t  pid			__attribute__((packed));
  uint32_t  uid			__attribute__((packed));
  uint32_t  fd			__attribute__((packed));
  uint32_t  inode		__attribute__((packed));
  uint8_t   com[SEBEK_HEADER_COMMAND_LEN];
  uint32_t  length		__attribute__((packed));
}sebek_hdr, *psebek_hdr;

struct sbk_sock_rec {
    uint32_t  dip       __attribute__((packed));
    uint16_t  dport     __attribute__((packed));
    uint32_t  sip       __attribute__((packed));
    uint16_t  sport     __attribute__((packed));
    uint16_t  call      __attribute__((packed));
    uint8_t   proto     __attribute__((packed));
};

typedef struct proc_infor_t
{
	uint32_t pid;
	uint32_t ppid;
	char pname[PROCNAMELEN+1];
}proc_info_t, *pproc_info_t;

bool qebek_read_ulong(CPUX86State *env, target_ulong address, uint32_t *value);
bool qebek_read_uword(CPUX86State *env, target_ulong address, uint16_t *value);
bool qebek_read_byte(CPUX86State *env, target_ulong address, uint8_t *value);
bool qebek_read_raw(CPUX86State *env, target_ulong address, uint8_t* buffer, int len);

bool qebek_get_current_pid(CPUX86State *env, uint32_t *pid);

void qebek_log_data(CPUX86State *env, uint16_t type, uint8_t *data, uint32_t len);
bool qebek_get_proc_info(CPUX86State *env, proc_info_t *proc_info);

#endif
