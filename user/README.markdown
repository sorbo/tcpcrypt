Tcpcrypt
========

[Tcpcrypt homepage](http://tcpcrypt.org)

Installing tcpcrypt
-------------------

    git clone git://github.com/sorbo/tcpcrypt.git
    cd tcpcrypt/user
    make

Test drive
---------- 

    # in tcpcrypt/user
    sudo ./launch_tcpcryptd.sh & 
    nc -l 7777 &
    sudo tcpdump -i lo -n -s0 -vvvv -X tcp port 7777 &
    echo hello, world! | nc localhost 7777
    
    # clean up
    sudo killall tcpcryptd tcpdump

You can also go to [http://tcpcrypt.org/fame.php](http://tcpcrypt.org/fame.php)
while tcpcryptd is running. You'll see a text box where you can post a
message to the tcpcrypt Hall of Fame, and your tcpcrypt session ID is displayed
at the bottom of the page.

More info
---------

... TODO ...