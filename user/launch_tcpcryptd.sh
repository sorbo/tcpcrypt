#!/bin/sh

OSNAME=`uname -s`
PORT=${1:-80}
PORT2=${2:-7777}

TCPCRYPTD=`dirname $0`/src/tcpcryptd
DIVERT_PORT=666
PIDFILE=/var/run/tcpcrypt.pid

start_tcpcryptd() {
    LD_LIBRARY_PATH=lib/ $TCPCRYPTD $OPTS -p $DIVERT_PORT &
    echo $! > $PIDFILE
    wait $!
}

ee() {
    echo $*
    eval $*
}

linux_set_iptables() {
    echo Tcpcrypting port 80 and 7777...
    ee iptables -I INPUT  -p tcp --sport $PORT -j NFQUEUE --queue-num $DIVERT_PORT
    ee iptables -I OUTPUT -p tcp --dport $PORT -j NFQUEUE --queue-num $DIVERT_PORT
    ee iptables -I INPUT  -p tcp --dport $PORT2 -j NFQUEUE --queue-num $DIVERT_PORT
    ee iptables -I INPUT  -p tcp --sport $PORT2 -j NFQUEUE --queue-num $DIVERT_PORT
    ee iptables -I OUTPUT -p tcp --dport $PORT2 -j NFQUEUE --queue-num $DIVERT_PORT
    ee iptables -I OUTPUT -p tcp --sport $PORT2 -j NFQUEUE --queue-num $DIVERT_PORT
}

linux_unset_iptables() {
    echo Removing iptables rules and quitting tcpcryptd...
    iptables -D INPUT  -p tcp --sport $PORT -j NFQUEUE --queue-num $DIVERT_PORT
    iptables -D OUTPUT -p tcp --dport $PORT -j NFQUEUE --queue-num $DIVERT_PORT
    iptables -D INPUT  -p tcp --dport $PORT2 -j NFQUEUE --queue-num $DIVERT_PORT
    iptables -D INPUT  -p tcp --sport $PORT2 -j NFQUEUE --queue-num $DIVERT_PORT
    iptables -D OUTPUT -p tcp --dport $PORT2 -j NFQUEUE --queue-num $DIVERT_PORT
    iptables -D OUTPUT -p tcp --sport $PORT2 -j NFQUEUE --queue-num $DIVERT_PORT
    exit
}

bsd_set_ipfw() {
    echo Tcpcrypting port 80 and 7777...
    ipfw 02 add divert $DIVERT_PORT tcp from any to any $PORT
    ipfw 03 add divert $DIVERT_PORT tcp from any $PORT to any
    ipfw 04 add divert $DIVERT_PORT tcp from any to any $PORT2
    ipfw 05 add divert $DIVERT_PORT tcp from any $PORT2 to any
}

bsd_unset_ipfw() {
    echo Removing ipfw rules and quitting tcpcryptd...
    ipfw delete 02 03 04 05
    exit
}

win_start_tcpcryptd() {
    MAC_ADDR=`ipconfig /all | grep 'Physical Address'| head -n 1 | sed 's/\s*Physical Address\(\. \)*: \(.*\)/\2/' | sed 's/-/:/g'`
    echo Using MAC address $MAC_ADDR...
    LD_LIBRARY_PATH=lib/ $TCPCRYPTD $OPTS -p $DIVERT_PORT -x $MAC_ADDR &
    echo $! > $PIDFILE
    wait $!    
}

check_root() {
    if [ `whoami` != "root" ]
    then
        echo "must be root"
        exit 1
    fi
}

check_ssh() {
    if [ -n "$SSH_CONNECTION" ]
    then
        read -p 'Command may disrupt existing ssh connections. Proceed? [y/N] ' C
        if [ "$C" != "y" ]
        then
            exit 1
        fi
    fi
}

check_existing_tcpcryptd() {
    P=`ps axo pid,comm | grep tcpcryptd`
    if [ $? -eq 0 ]
    then
        read -p "tcpcryptd already running with pid $P. Proceed? [y/N] " C
        if [ "$C" != "y" ]
        then
            exit 1
        fi
    fi
}


#check_ssh

case "$OSNAME" in
    Linux)
        check_existing_tcpcryptd
        check_root
        linux_set_iptables
        trap linux_unset_iptables 2 # trap SIGINT to remove iptables rules before exit
        start_tcpcryptd
        linux_unset_iptables
        ;;
    FreeBSD|Darwin)
        check_existing_tcpcryptd
        check_root
        bsd_set_ipfw
        trap bsd_unset_ipfw 2
        start_tcpcryptd
        bsd_unset_ipfw
        ;;
    [Cc][Yy][Gg][Ww][Ii][Nn]*)
        win_start_tcpcryptd
        ;;
esac

