#ifndef __TCPCRYPT_TCPCRYPT_STRINGS_H__
#define __TCPCRYPT_TCPCRYPT_STRINGS_H__

static char *REQS[] = {
	"GET /check HTTP/1.0\r\n"
        "Host: check.tcpcrypt.org\r\n"
        "\r\n",

	"MORTEasldkfjasldkfjaslkfjaslfkjasdlfkjas",

	"GHGHHGHGHGHREHEHGEHRGHERHGHERG",
};

static char *TEST_REPLY = "HTTP/1.0 200 OK\r\n"
			  "\r\n";

#endif /* __TCPCRYPT_TCPCRYPT_STRINGS_H__ */
