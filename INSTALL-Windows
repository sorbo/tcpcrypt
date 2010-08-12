Installing tcpcrypt on Windows
==============================



Note: Tcpcrypt has only been tested on Windows XP 32-bit.

Compiling
=========

You need Cygwin and the following packages to compile tcpcrypt:

* libopenssl098
* openssl-devel
* gcc
* make (GNU make)

To compile, run `make` from the tcpcrypt/user directory.

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
the pre-compiled tcpcryptd binary for Cygwin at
[http://tcpcrypt.org/tcpcryptd.cygwin](http://tcpcrypt.org/tcpcryptd.cygwin). If
you will use the launch script (below), move this file to
tcpcrypt/user/tcpcrypt/tcpcryptd.exe, which is where the launch script expects
it.

Running
=======

After installing the divert socket driver, run the tcpcryptd daemon with the
following command, from tcpcrypt/user:

    ./launch_tcpcryptd.sh

By default, this script tells tcpcryptd to use the first network interface
listed in `ipconfig /all`. If you want to use a different interface, run
tcpcryptd manually:

    LD_LIBRARY_PATH=lib/ tcpcrypt/tcpcryptd -x 0a:1b:2c:3d:4f:6a


Test drive
==========

Once tcpcryptd is running, see README.markdown for ways to try it out. 
