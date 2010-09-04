Installing tcpcrypt on Mac OS X
===============================

Compiling
---------

Tcpcrypt does not depend on non-standard libs on Mac OS X, so just run:

    cd tcpcrypt/user
    ./configure
    make

Optional: running `make install` will install `libtcpcrypt` and tcpcrypt
headers, for building apps that use tcpcrypt's session ID.

Running
-------

The launch script (in tcpcrypt/user) starts tcpcryptd and sets up your firewall
to send port 80 and 7777 packets through tcpcrypt:

    ./launch_tcpcryptd.sh

With tcpcryptd running, open
[http://tcpcrypt.org/test.php](http://tcpcrypt.org/test.php) to try it out.

More info
----------

See the included `README.markdown` file for more ways to try out tcpcrypt and
for troubleshooting help.

See `INSTALL-FreeBSD` for firewall setup instructions. (FreeBSD and Mac OS X use
the same firewall, `ipfw`.)
