#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>

#include "inc.h"
#include "tcpcrypt_divert.h"
#include "tcpcryptd.h"

#include <windivert.h>

#define MAC_SIZE	14

static HANDLE _h;

static WINAPI DWORD reader(void *arg)
{
	int s;
	struct sockaddr_in s_in;
	UINT r;
	unsigned char buf[2048];
	
	// XXX: the DIVERT_ADDRESS is stored in the ethhdr.
	PDIVERT_ADDRESS addr = (PDIVERT_ADDRESS)buf;

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket()");

	memset(&s_in, 0, sizeof(s_in));

	s_in.sin_family	     = PF_INET;
	s_in.sin_addr.s_addr = inet_addr("127.0.0.1");
	s_in.sin_port	     = htons(619);

	while (1) {
		memset(buf, 0, MAC_SIZE);
		if (!DivertRecv(_h, buf + MAC_SIZE, sizeof(buf) - MAC_SIZE,
			   addr, &r))
			err(1, "DivertRead()");
		
		if (sendto(s, (void*) buf, r + MAC_SIZE, 0,
			   (struct sockaddr*) &s_in, sizeof(s_in)) !=
			   r + MAC_SIZE)
			err(1, "sendto()");
	}

	return 0;
}

int do_divert_open(void)
{
	// XXX i know this is lame
	struct sockaddr_in s_in;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s == -1)
		err(1, "socket()");

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family	     = PF_INET;
	s_in.sin_addr.s_addr = inet_addr("127.0.0.1");
	s_in.sin_port	= htons(619);

	if (bind(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind(divert)");

	// XXX: Currently TCP port 80 only...
	_h = DivertOpen(
		"ip and "
		"((outbound and tcp.DstPort == 80) or "
		" (inbound and tcp.SrcPort == 80) or "
		" (outbound and tcp.DstPort == 7777) or "
		" (inbound and tcp.SrcPort == 7777)"
		") and "
		"ip.DstAddr != 127.0.0.1 and "
		"ip.SrcAddr != 127.0.0.1",
		WINDIVERT_LAYER_NETWORK, 0, 0);

	if (_h == INVALID_HANDLE_VALUE)
		err(1, "DivertOpen()");

	if (!CreateThread(NULL, 0, reader, NULL, 0, NULL))
		err(1, "CreateThread()");

	return s;
}

void do_divert_close(int s)
{
	DivertClose(_h);
}

int do_divert_read(int s, void *buf, int len)
{
	return recv(s, buf, len, 0);
}

int do_divert_write(int s, void *buf, int len)				      
{
	UINT r;
	PDIVERT_ADDRESS addr = (PDIVERT_ADDRESS)buf;

	if (len <= MAC_SIZE)
		return -1;

	buf += MAC_SIZE;
	len -= MAC_SIZE;

	if (!DivertSend(_h, buf, len, addr, &r))
		return -1;

	return r + MAC_SIZE;
}

