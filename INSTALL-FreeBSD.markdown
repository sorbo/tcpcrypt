Installing tcpcrypt on FreeBSD
==============================

Dependencies
------------

Enable `ipfw` and divert sockets, if you haven't already (reboot required):

    echo 'firewall_enable="YES"' >> /etc/rc.conf
    echo 'firewall_type="open"' >> /etc/rc.conf
    echo 'ipfw_load="YES"' >> /boot/loader.conf
    echo 'ipdivert_load="YES"' >> /boot/loader.conf
    reboot

Tcpcrypt also requires OpenSSL >= 0.9.8, which is provided by the
`security/openssl` port.


Compiling
---------

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

See `contrib/freebsd` for a FreeBSD rc script that loads tcpcryptd on system startup.

More info
----------

See the included `README.markdown` file for more ways to try out tcpcrypt and
for troubleshooting help.


Firewall setup
==============

The included `launch_tcpcryptd.sh` script sets up reasonable firewall rules, but for more complex setups, add your own `divert` rules.

For example, this will divert all TCP packets to tcpcryptd (on divert port 666), and it will be rule #1.

    ipfw 01 add divert 666 tcp from any to any

It's important that tcpcrypt divert rules are high on the list since tcpcryptd
modifies the packet quite a lot, including sequence numbers, so other items
(e.g., natd) may get confused if tcpcryptd doesn't do its magic first.

