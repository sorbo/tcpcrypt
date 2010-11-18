Installing tcpcrypt on Windows
==============================

Compiling
=========

Only cross-compiling for Windows on Linux (using mingw) is supported right now. You can almost certainly compile the Windows version on Windows itself, but we haven't done that yet (if you have, contact us).

Using mingw, run the following commands to cross-compile tcpcrypt for Windows
on a Linux host.

    cd tcpcrypt/user
    ./configure CFLAGS="-mwin32 -D__WIN32__ -I/home/sqs/src/mingw/OpenSSL-Win32/include" LDFLAGS=" -L/home/sqs/src/mingw/OpenSSL-Win32/ " --host=i586-mingw32msvc
    make

Replace `<path-to-mingw-openssl>` with the path to OpenSSL compiled for
Windows. You can download binaries from
[http://www.slproweb.com/products/Win32OpenSSL.html](http://www.slproweb.com/products/Win32OpenSSL.html)
(use the 'Win32 OpenSSL v1.0.0a' link) and run the installer with Wine. Then
rename `libeay32.dll` to `libcrypto.dll` in the root OpenSSL folder (that you
just installed into). There's almost certainly a cleaner way to do this, but
this is the quickest way.

Optional: running `make install` will install `libtcpcrypt` and tcpcrypt
headers, for building apps that use tcpcrypt's session ID.


Installing
==========

The Windows implementation of tcpcrypt has two components: the kernel divert
socket driver and the userland daemon.

Installing the kernel divert socket driver
------------------------------------------

1. Open the Properties window of your network interface
2. Click "Install..."
3. Choose "Service", click "Add...", and then "Have Disk..."
4. Browse to the tcpcrypt/kernel/win directory (with netsf.inf), click "Open", and
   then click "OK"
5. With "Passthru Driver" selected, click "OK"

Note: Installing this driver will disrupt existing connections. You can easily
enable and disable it from your network interface's Properties window.

Getting the userland daemon
---------------------------

If you followed the compilation steps above, you're done. Otherwise, download
the pre-compiled tcpcryptd binary for Windows at
[http://tcpcrypt.org/](http://tcpcrypt.org/). If you will use the launch script
(below), move this file to tcpcrypt/user/tcpcrypt/tcpcryptd.exe, which is where
the launch script expects it.

Or you can just download the precompiled Windows GUI version at the link above.

Running
=======

After installing the divert socket driver, run the tcpcryptd daemon with the
following command, from tcpcrypt/user:

    ./launch_tcpcryptd.sh

By default, this script tells tcpcryptd to use the first network interface
listed in `ipconfig /all`. If you want to use a different interface, run
tcpcryptd manually:

    tcpcrypt/tcpcryptd -x 0a:1b:2c:3d:4f:6a


Test drive
==========

Once tcpcryptd is running, see README.markdown for ways to try it out. 
