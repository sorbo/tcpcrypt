#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "inc.h"
#include "divert.h"
#include "tcpcryptd.h"

static HANDLE _h, _h2;

// XXX signal 1 byte and have main thread ReadFile directly.  Peek here.
static WINAPI DWORD reader(void *arg)
{
	int s;
	struct sockaddr_in s_in;
        ULONG r;
        int rc;
	unsigned char buf[2048];
	
	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket()");

	memset(&s_in, 0, sizeof(s_in));

	s_in.sin_family	     = PF_INET;
	s_in.sin_addr.s_addr = inet_addr("127.0.0.1");
	s_in.sin_port	     = htons(619);

	while (1) {
		rc = ReadFile(_h, buf, sizeof(buf), &r, NULL);
		if (!rc)
			err(1, "ReadFile()");

		if (sendto(s, (void*) buf, r, 0,
			   (struct sockaddr*) &s_in, sizeof(s_in)) != r)
			err(1, "sendto()");
	}

	return 0;
}

int do_divert_open(char *dev)
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
	s_in.sin_port        = htons(619);

	if (bind(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind(divert)");

        _h = CreateFile(dev,
                GENERIC_READ,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                INVALID_HANDLE_VALUE);

        _h2 = CreateFile(dev,
                 GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                INVALID_HANDLE_VALUE);

	if (_h == INVALID_HANDLE_VALUE || _h2 == INVALID_HANDLE_VALUE)
		err(1, "CreateFile()");

	if (!CreateThread(NULL, 0, reader, NULL, 0, NULL))
		err(1, "CreateThread()");

        return s;
}

void do_divert_close(int s)
{
        CloseHandle(_h);
        CloseHandle(_h2);
}

int do_divert_read(int s, void *buf, int len)
{
	return recv(s, buf, len, 0);
}

int do_divert_write(int s, void *buf, int len)                                      
{                                                                                   
        ULONG r;
        int rc;

        rc = WriteFile(_h2, buf, len, &r, NULL);
        if (!rc)
                return -1;

        return r;
}
