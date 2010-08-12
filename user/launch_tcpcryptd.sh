#!/bin/sh

OSNAME=`uname -s`
PORT=${1:-80}

TCPCRYPTD=`dirname $0`/tcpcrypt/tcpcryptd
TCPCRYPTD_DIVERT_PORT=666

start_tcpcryptd() {
    LD_LIBRARY_PATH=lib/ $TCPCRYPTD $OPTS -p $TCPCRYPTD_DIVERT_PORT
}

ee() {
    echo $*
    eval $*
}

linux_set_iptables() {
    echo Tcpcrypting port 80 and all local traffic...
    ee iptables -I INPUT  -p tcp --sport $PORT -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    ee iptables -I OUTPUT -p tcp --dport $PORT -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    ee iptables -I INPUT  -p tcp -i lo         -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    ee iptables -I OUTPUT -p tcp -o lo         -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
}

linux_unset_iptables() {
    echo Removing iptables rules and quitting tcpcryptd...
    iptables -D INPUT  -p tcp --sport $PORT -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    iptables -D OUTPUT -p tcp --dport $PORT -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    iptables -D INPUT  -p tcp -i lo         -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    iptables -D OUTPUT -p tcp -o lo         -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    exit
}

bsd_set_ipfw() {
    echo Tcpcrypting port 80 and all local traffic...
    ipfw -q 01 add divert $TCPCRYPTD_DIVERT_PORT tcp from any 80 to any
    ipfw -q 02 add divert $TCPCRYPTD_DIVERT_PORT tcp from any to any 80
    ipfw -q 03 add divert $TCPCRYPTD_DIVERT_PORT tcp from any to any via lo0
}

bsd_unset_ipfw() {
    echo Removing ipfw rules and quitting tcpcryptd...
    ipfw delete 01 02 03
}

win_start_tcpcryptd() {
    MAC_ADDR=`ipconfig /all | grep 'Physical Address'| head -n 1 | sed 's/\s*Physical Address\(\. \)*: \(.*\)/\2/' | sed 's/-/:/g'`
    echo Using MAC address $MAC_ADDR...
    LD_LIBRARY_PATH=lib/ $TCPCRYPTD $OPTS -p $TCPCRYPTD_DIVERT_PORT -x $MAC_ADDR
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
        read -p "tcpcryptd already running with pid$P. Proceed? [y/N] " C
        if [ "$C" != "y" ]
        then
            exit 1
        fi
    fi
}


check_ssh

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

