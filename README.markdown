Tcpcrypt
========

Tcpcrypt is a protocol that attempts to encrypt (almost) all of your network
traffic. Unlike other security mechanisms, Tcpcrypt works out of the box: it
requires no configuration, no changes to applications, and your network
connections will continue to work even if the remote end does not support
Tcpcrypt, in which case connections will gracefully fall back to standard
clear-text TCP.

Tcpcrypt supports Linux, Mac OS X, Windows, and FreeBSD.

For more information, see [tcpcrypt.org](http://tcpcrypt.org).

Installing tcpcrypt
-------------------

    git clone git://github.com/sorbo/tcpcrypt.git
    cd tcpcrypt/user
    ./configure
    make
    sudo ./launch_tcpcryptd.sh

The launch script starts tcpcryptd and adds firewall rules to divert Web and
local port 7777 (an arbitrarily chosen port number) traffic to tcpcryptd. When the script exits (on Ctrl-C or
`kill`), it restores your firewall config to its former state--**no permanent
changes are made**.

On Linux, you must first install libnfnetlink, libnetfilter_queue, and libcap.

Optional: running `make install` will install `libtcpcrypt` and tcpcrypt
headers, for building apps that use tcpcrypt's session ID.

Try it out
---------- 

Go to [http://tcpcrypt.org/test.php](http://tcpcrypt.org/test.php) with
tcpcryptd running. If tcpcrypt is working, you'll be able to join the
tcpcrypt Hall of Fame and your tcpcrypt session ID will be displayed at the
bottom of the page.

Now let's examine the packets going over the wire by starting tcpdump and then
reloading the URL above.

    sudo tcpdump -X -s0 host tcpcrypt.org

Compare this tcpdump output, which appears encrypted (or at least unreadable),
with the cleartext packets you would see without tcpcryptd running.

A final netcat example:

    # in tcpcrypt/user
    sudo ./launch_tcpcryptd.sh & 
    nc -l 7777 &
    sudo tcpdump -i lo -n -s0 -vvvv -X tcp port 7777 &
    echo hello, world! | nc localhost 7777
    
    # clean up
    sudo killall tcpcryptd tcpdump


Troubleshooting
---------------

If it's not working, the most likely causes are the following.

   * Your browser already had an open, non-tcpcrypted TCP connection to
     tcpcrypt.org before you ran the launch script. Quit and reopen your
     browser, wait 30 seconds, or use a different browser to retrieve the
     tcpcrypt.org URL.

   * There's a conflict with your existing firewall rules. See the
     firewall setup section in the install guide for your platform.

Visit [http://wiki.github.com/sorbo/tcpcrypt/troubleshooting](http://wiki.github.com/sorbo/tcpcrypt/troubleshooting) if you're still
unable to make it work.

To build the `test_tcpcrypt` utility, run `make check` from `user/`. Run `test_tcpcrypt -v` to see the various tests that it can run.

More info
---------

The `INSTALL-*` files have more detailed installation and firewall setup instructions. See [tcpcrypt.org](http://tcpcrypt.org) for general info, including the [protocol specification](http://tcpcrypt.org/docs.php) and the [tcpcrypt paper, "The case for ubiquitous transport-level encryption"](http://tcpcrypt.org/tcpcrypt.pdf), presented at USENIX Security 2010.

The code repository lives at [http://github.com/sorbo/tcpcrypt](http://github.com/sorbo/tcpcrypt).
