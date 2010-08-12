Tcpcrypt
========

<<<<<<< HEAD
Tcpcrypt is a protocol that attempts to encrypt (almost) all of your network
traffic. Unlike other security mechanisms, Tcpcrypt works out of the box: it
requires no configuration, no changes to applications, and your network
connections will continue to work even if the remote end does not support
Tcpcrypt, in which case connections will gracefully fall back to standard
clear-text TCP.

Tcpcrypt supports Linux, Mac OS X, Windows, and FreeBSD.

For more information, see the [tcpcrypt.org](http://tcpcrypt.org).
=======
[Tcpcrypt homepage](http://tcpcrypt.org)
>>>>>>> 0886a44356ca4b87e8bee6a23daf79d071e74a9b

Installing tcpcrypt
-------------------

    git clone git://github.com/sorbo/tcpcrypt.git
    cd tcpcrypt/user
    make
<<<<<<< HEAD
    ./launch_tcpcryptd.sh

The launch script starts tcpcryptd and adds firewall rules to divert Web and local port 7777 traffic to tcpcryptd.

On Linux, you must first install libnfnetlink, libnetfilter_queue, and libcap.

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

=======

Test drive
---------- 

>>>>>>> 0886a44356ca4b87e8bee6a23daf79d071e74a9b
    # in tcpcrypt/user
    sudo ./launch_tcpcryptd.sh & 
    nc -l 7777 &
    sudo tcpdump -i lo -n -s0 -vvvv -X tcp port 7777 &
    echo hello, world! | nc localhost 7777
    
    # clean up
    sudo killall tcpcryptd tcpdump

<<<<<<< HEAD
=======
You can also go to [http://tcpcrypt.org/fame.php](http://tcpcrypt.org/fame.php)
while tcpcryptd is running. You'll see a text box where you can post a message
to the tcpcrypt Hall of Fame, and your tcpcrypt session ID is displayed at the
bottom of the page.
>>>>>>> 0886a44356ca4b87e8bee6a23daf79d071e74a9b

More info
---------

<<<<<<< HEAD
The INSTALL-* files have more detailed installation and firewall setup instructions. See [tcpcrypt.org](http://tcpcrypt.org) for general info, including the [protocol specification](http://tcpcrypt.org/docs.php).

The code repository lives at [http://github.com/sorbo/tcpcrypt](http://github.com/sorbo/tcpcrypt).
=======
... TODO ...
>>>>>>> 0886a44356ca4b87e8bee6a23daf79d071e74a9b
