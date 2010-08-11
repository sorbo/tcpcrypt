#!/bin/sh

OSNAME=`uname -s`
ENCRYPT_PORT=80

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
    ee iptables -I INPUT -p tcp --sport $ENCRYPT_PORT -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    ee iptables -I OUTPUT -p tcp --dport $ENCRYPT_PORT -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    ee iptables -I INPUT -p tcp -i lo -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    ee iptables -I OUTPUT -p tcp -o lo -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
}

linux_unset_iptables() {
    echo Removing iptables rules and quitting tcpcryptd...
    iptables -D INPUT -p tcp --sport $ENCRYPT_PORT -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    iptables -D OUTPUT -p tcp --dport $ENCRYPT_PORT -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    iptables -D INPUT -p tcp -i lo -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    iptables -D OUTPUT -p tcp -o lo $ENCRYPT_PORT2 -j NFQUEUE --queue-num $TCPCRYPTD_DIVERT_PORT
    exit
}

if [ `whoami` != "root" ]
then
    echo "must be root"
    exit 1
fi

case "$OSNAME" in
    Linux)
        linux_set_iptables
        trap linux_unset_iptables 2 # trap SIGINT to remove iptables rules before exit
        start_tcpcryptd
        linux_unset_iptables
esac

